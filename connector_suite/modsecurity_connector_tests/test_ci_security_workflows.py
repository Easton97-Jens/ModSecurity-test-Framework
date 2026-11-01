"""Focused static contracts for the repository's CI-security workflows."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import ast
import os
import re
import subprocess
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

import yaml
from modsecurity_test_framework.workflow_sources import read_connector_workflow
from yaml.tokens import AliasToken, AnchorToken, KeyToken, ScalarToken, TagToken
from modsecurity_test_framework.product_sources.ci.lib.framework_revision_pins import load_project_version_pins


ROOT = connector_root()
WORKFLOWS = source_path('.github/workflows', root=ROOT)
WORKFLOW_PATTERNS = ("*.yml", "*.yaml")
PERMISSION_FIXTURES = source_path('ci/fixtures/workflow-permission-contract', root=ROOT)
SHA_PIN = re.compile(r"^[a-z\d_.-]+(?:/[a-z\d_.-]+)+@[a-f\d]{40}\s+# v\d", re.MULTILINE)
SHELL_CONTINUATION = re.compile(r"\\\r?\n[ \t]*")
JOB_HEADER = re.compile(r"^ {2}(?P<name>[A-Za-z0-9_-]+):\s*$")
STEP_HEADER = re.compile(r"^(?P<indent>\s*)-\s")
GO_MODULE_REQUIREMENT = re.compile(
    r"^(?P<module>[A-Za-z0-9][A-Za-z0-9._/-]*)\s+v"
    r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?:\s+//.*)?$"
)
PCRE2_SHA256 = "47fe8c99461250d42f89e6e8fdaeba9da057855d06eb7fc08d9ca03fd08d7bc7"
PROTECTED_NGINX_BROKER_CALLER_WORKFLOW = "run-protected-nginx-root-broker.yml"
PROTECTED_NGINX_BROKER_SHA = "8ae707d72f1a8acb25d239e55e28a73cbc7522b1"
PROTECTED_NGINX_BROKER_FRAMEWORK_SHA = "99a7985c1be92a2297b1b59208f64df6768f2cbf"
PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE = (
    "Easton97-Jens/ModSecurity-conector/.github/workflows/nginx-root-broker.yml@"
    + PROTECTED_NGINX_BROKER_SHA
)
PROJECT_VERSION_PINS = load_project_version_pins(ROOT)
WITH_CRS_NO_MRTS_FRAMEWORK_SHA = PROJECT_VERSION_PINS["framework_sha"]
WITH_CRS_NO_MRTS_MRTS_SHA = PROJECT_VERSION_PINS["mrts_sha"]
PROTECTED_NGINX_BROKER_CALLER_MASTER_GATE_TERMS = frozenset(
    {
        "github.event_name == 'workflow_dispatch'",
        "github.repository == 'Easton97-Jens/ModSecurity-conector'",
        "github.event.repository.fork == false",
        "github.ref == 'refs/heads/master'",
        "github.event.repository.default_branch == 'master'",
    }
)
LOCK_PATH = source_path('ci/tooling/security-tools.lock.yml', root=ROOT)
LOCKED_ACTION_USE = re.compile(
    r"(?P<prefix>uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?@)"
    r"(?P<sha>[a-f0-9]{40})(?:\s+#\s*v[^\n]+)?"
)
SUBMODULE_PUBLISHER_NORMALIZED_SHA256 = "cd15b994b60eb68be42bca984054bab125c7be661c3baf7410f0528b34e29fea"
SONAR_NATIVE_WORKFLOW_NORMALIZED_SHA256 = "12cac10473c7c8ba2366289d92009de69608e4fe63e4cb69fbe98f8d877173f5"
SUBMODULE_PUBLISHER_APP_TOKEN_ACTION = "actions/create-github-app-token"
SUBMODULE_PUBLISHER_APP_TOKEN_INPUTS = {
    "client-id": "${{ vars.WORKFLOW_UPDATER_APP_CLIENT_ID }}",
    "private-key": "${{ secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY }}",
    "owner": "${{ github.repository_owner }}",
    "repositories": "${{ github.repository }}",
    "permission-contents": "write",
    "permission-pull-requests": "write",
    "permission-workflows": "write",
}
SUBMODULE_PUBLISHER_APP_TOKEN_OUTPUT = "${{ steps.publisher_app_token.outputs.token }}"
AUTO_MERGE_DISABLED_QUERY = (
    "--jq 'if (has(\"auto_merge\") and (.auto_merge == null)) then \"null\" "
    "else \"auto-merge-present\" end'"
)
READONLY_SUBMODULE_SANDBOX_CALL = " ".join(
    (
        "python3 ci/tools/prepare-readonly-submodule-validation-sandbox.py",
        '--source-root "$GITHUB_WORKSPACE"',
        '--framework-root "$GITHUB_WORKSPACE/modules/ModSecurity-test-Framework"',
        '--write-root "$VALIDATION_WRITE_ROOT"',
        '--runner-temp "$RUNNER_TEMP"',
        "--validator-user modsecurity-validator",
        "--validator-group modsecurity-validator",
    )
)
READONLY_SUBMODULE_WRITE_ROOT = "$RUNNER_TEMP/modsecurity-readonly-validation.XXXXXX"
READONLY_SUBMODULE_EXTERNAL_ROOT = "$VALIDATION_WRITE_ROOT/external"
READONLY_SUBMODULE_NAMESPACE_CALL = " ".join(
    (
        "sudo -n python3 ci/tools/run-readonly-submodule-validation-namespace.py",
        '--source-root "$GITHUB_WORKSPACE"',
        '--framework-root "$GITHUB_WORKSPACE/modules/ModSecurity-test-Framework"',
        '--write-root "$VALIDATION_WRITE_ROOT"',
        '--external-root "$VALIDATION_WRITE_ROOT/external"',
        "--validator-user modsecurity-validator",
        "--validator-group modsecurity-validator",
        '--python "$EXPECTED_PYTHON"',
        '--namespace-parent "$namespace_parent"',
    )
)
READONLY_SUBMODULE_SANDBOX_READY = (
    "READONLY_SUBMODULE_VALIDATION_SANDBOX_READY\\ external=*\\ source_inventory_sha256=*"
)
READONLY_SUBMODULE_NAMESPACE_COMPLETE = "READONLY_SUBMODULE_VALIDATION_NAMESPACE_COMPLETE"
READONLY_SUBMODULE_VERIFY_GATE = (
    "if: ${{ always() && steps.prepare-readonly-candidate-sandbox.outcome == 'success' }}"
)
READONLY_SUBMODULE_CLEANUP_GATE = (
    "if: ${{ always() && steps.create-readonly-candidate-sandbox-guard.outputs.write_root != '' }}"
)
READONLY_SUBMODULE_CLEANUP_CALL = " ".join(
    (
        "python3 ci/tools/prepare-readonly-submodule-validation-sandbox.py",
        "--cleanup",
        '--source-root "$GITHUB_WORKSPACE"',
        '--framework-root "$GITHUB_WORKSPACE/modules/ModSecurity-test-Framework"',
        '--write-root "$VALIDATION_WRITE_ROOT"',
        '--runner-temp "$RUNNER_TEMP"',
    )
)
SUBMODULE_CANDIDATE_STATE_HELPER = "ci/tools/validate-submodule-candidate-state.py"
SUBMODULE_CANDIDATE_BASELINE_CALL = " ".join(
    (
        f"python3 {SUBMODULE_CANDIDATE_STATE_HELPER}",
        "capture-parent-baseline",
        '--parent-root "$GITHUB_WORKSPACE"',
        '--github-env "$GITHUB_ENV"',
    )
)
SUBMODULE_CANDIDATE_STATE_CALL = " ".join(
    (
        f"python3 {SUBMODULE_CANDIDATE_STATE_HELPER}",
        "validate",
        '--parent-root "$GITHUB_WORKSPACE"',
        '--submodule-path "$SUBMODULE_PATH"',
        '--current-gitlink-sha "$CURRENT_GITLINK_SHA"',
        '--candidate-sha "$CANDIDATE_SHA"',
        '--expected-parent-head "$EXPECTED_PARENT_HEAD"',
        '--expected-parent-hooks-sha256 "$EXPECTED_PARENT_HOOKS_SHA256"',
        '--allowed-nested-gitlink-path "$ALLOWED_NESTED_GITLINK_PATH"',
        '--allowed-nested-submodule-url "$ALLOWED_NESTED_SUBMODULE_URL"',
    )
)
SUBMODULE_VALIDATE_ONLY_INPUT = """\
  workflow_dispatch:
    inputs:
      validate_only:
        description: Run the non-publishing exact-ref validator only.
        required: false
        default: false
        type: boolean
"""
SUBMODULE_VALIDATE_ONLY_EVENT = (
    "github.event_name == 'workflow_dispatch' && "
    "github.event.inputs.validate_only == 'true'"
)
SUBMODULE_VALIDATE_ONLY_REPOSITORY = "github.repository == 'Easton97-Jens/ModSecurity-conector'"
SUBMODULE_VALIDATE_ONLY_BRANCH = (
    "github.ref == 'refs/heads/fix/ci-enforce-readonly-submodule-validation'"
)
SUBMODULE_VALIDATE_ONLY_RETIRED_PR280_BRANCH = (
    "github.ref == 'refs/heads/agent/framework-apr-util-submodule-validation'"
)
SUBMODULE_VALIDATE_ONLY_PROTECTED_FLAG = "github.ref_protected == true"
SUBMODULE_VALIDATE_ONLY_PROTECTED_MASTER = (
    "(github.ref == 'refs/heads/master' && "
    "github.event.repository.default_branch == 'master' && "
    f"{SUBMODULE_VALIDATE_ONLY_PROTECTED_FLAG})"
)
SUBMODULE_VALIDATE_ONLY_REF_ALLOWLIST = (
    f"({SUBMODULE_VALIDATE_ONLY_BRANCH} || {SUBMODULE_VALIDATE_ONLY_PROTECTED_MASTER})"
)
SUBMODULE_VALIDATE_ONLY_MANUAL_PREDICATE = (
    f"{SUBMODULE_VALIDATE_ONLY_EVENT} && "
    f"{SUBMODULE_VALIDATE_ONLY_REPOSITORY} && "
    "github.event.repository.fork == false && "
    f"{SUBMODULE_VALIDATE_ONLY_REF_ALLOWLIST}"
)
SUBMODULE_VALIDATE_ONLY_MASTER_EXCLUSION = (
    "(github.event_name == 'workflow_dispatch' && "
    "github.event.inputs.validate_only != 'true')"
)
SUBMODULE_VALIDATE_ONLY_CHECKOUT_REF = (
    f"ref: ${{{{ {SUBMODULE_VALIDATE_ONLY_MANUAL_PREDICATE} && github.sha || "
    "github.event.repository.default_branch }}"
)
SUBMODULE_RESOLVER_GATE = (
    f"{SUBMODULE_VALIDATE_ONLY_REPOSITORY} && github.event.repository.fork == false && "
    "( ( github.ref == 'refs/heads/master' && "
    "github.event.repository.default_branch == 'master' && "
    f"{SUBMODULE_VALIDATE_ONLY_MASTER_EXCLUSION} ) || "
    f"( {SUBMODULE_VALIDATE_ONLY_EVENT} && "
    f"( {SUBMODULE_VALIDATE_ONLY_BRANCH} || {SUBMODULE_VALIDATE_ONLY_PROTECTED_MASTER} ) ) )"
)
SUBMODULE_VALIDATOR_GATE = (
    "needs.resolve-submodule-update.result == 'success' && "
    "needs.resolve-submodule-update.outputs.changed == 'true'"
)
SUBMODULE_PUBLISHER_GATE = (
    "needs.resolve-submodule-update.result == 'success' && "
    "needs.resolve-submodule-update.outputs.changed == 'true' && "
    "needs.resolve-submodule-update.outputs.validation_only == 'false' && "
    "needs.validate-submodule-update.result == 'success'"
)
SUBMODULE_LOCAL_GIT_CONTRACT_TESTS = (
    "modsecurity_connector_tests.test_validate_submodule_candidate_state",
    "modsecurity_connector_tests.test_update_submodules_local_git",
    "modsecurity_connector_tests.test_update_framework_versions",
    "modsecurity_connector_tests.test_verify_framework_candidate_contract",
)

WRITE_PERMISSION_KEYS = {
    "contents",
    "actions",
    "checks",
    "security-events",
    "pull-requests",
    "issues",
    "packages",
    "id-token",
    "attestations",
    "statuses",
}


def normalize_shell_script(script: str) -> str:
    """Normalize layout for static shell contracts without executing shell."""

    without_continuations = SHELL_CONTINUATION.sub(" ", script)
    return " ".join(without_continuations.split())


def assert_hash_locked_ci_test_dependency_installation(
    testcase: unittest.TestCase,
    validator: str,
    *,
    interpreter_contract_step: str,
    first_test_step: str,
) -> None:
    """Require the locked CI dependency before an import-sensitive workflow test."""

    normalized = normalize_shell_script(validator)
    install_step = "Install hash-locked CI test dependency"
    install_command = (
        "python3 ci/tools/install-ci-dependencies.py --ci-toolcache"
    )
    workflow_test = "python3 ci/tools/run-active-tests.py --group supply-chain"

    testcase.assertIn(install_step, validator)
    testcase.assertIn(install_command, normalized)
    testcase.assertIn("python3 -m pip check", normalized)
    testcase.assertLess(
        validator.index(interpreter_contract_step),
        validator.index(install_step),
    )
    testcase.assertLess(validator.index(install_step), validator.index(first_test_step))
    testcase.assertLess(normalized.index(install_command), normalized.index("python3 -m pip check"))
    testcase.assertLess(normalized.index(install_command), normalized.index(workflow_test))
    testcase.assertLess(normalized.index("python3 -m pip check"), normalized.index(workflow_test))


def has_exact_framework_gitlink_staging(script: str) -> bool:
    """Recognize only the narrowly scoped Framework gitlink index update."""

    normalized = normalize_shell_script(script)
    required = (
        'git update-index --add --cacheinfo '
        '"160000,$CANDIDATE_SHA,$SUBMODULE_PATH"'
    )
    return (
        required in normalized
        and "git add ." not in normalized
        and "git add -A" not in normalized
    )


def readonly_submodule_validator_errors(validator: str) -> list[str]:
    """Return violations of the root-side namespace validation boundary."""

    normalized = normalize_shell_script(validator)
    errors: list[str] = []
    required = (
        "Create private read-only candidate guard",
        "Install selected Apache native lifecycle prerequisites",
        "sudo apt-get install --no-install-recommends --yes build-essential apache2-dev libmodsecurity-dev",
        "Prepare reviewed Python dependency before runtime protection",
        "python3 ci/tools/install-ci-dependencies.py --ci-toolcache --framework-lock modules/ModSecurity-test-Framework/requirements-ci.lock",
        "python3 -m pip check",
        "id: create-readonly-candidate-sandbox-guard",
        READONLY_SUBMODULE_SANDBOX_CALL,
        READONLY_SUBMODULE_NAMESPACE_CALL,
        "sudo -n groupadd --system modsecurity-validator",
        "sudo -n useradd --system --no-create-home --shell /usr/sbin/nologin",
        'sudo -n chown root:root "$write_root"',
        'sudo -n chmod 0711 "$write_root"',
        'namespace_parent="$(sudo -n mktemp -d /tmp/modsecurity-readonly-namespace.XXXXXX)"',
        'sudo -n chown root:modsecurity-validator "$namespace_parent"',
        'sudo -n chmod 0750 "$namespace_parent"',
        "trap cleanup_namespace_parent EXIT",
        'sudo -n rmdir -- "$namespace_parent"',
        "sandbox_prepare_output=\"$(sudo -n python3 ci/tools/prepare-readonly-submodule-validation-sandbox.py",
        READONLY_SUBMODULE_SANDBOX_READY,
        "id: prepare-readonly-candidate-sandbox",
        "id: run-readonly-candidate-namespace",
        "continue-on-error: true",
        'namespace_status=0 namespace_output="$(sudo -n python3',
        ')" || namespace_status=$?',
        'printf \'%s\\n\' "$namespace_output"',
        'if [ "$namespace_status" -ne 0 ]; then exit "$namespace_status" fi',
        READONLY_SUBMODULE_NAMESPACE_COMPLETE,
        "Verify candidate source inventory and external outputs",
        READONLY_SUBMODULE_VERIFY_GATE,
        "--verify",
        SUBMODULE_CANDIDATE_BASELINE_CALL,
        SUBMODULE_CANDIDATE_STATE_CALL,
        'nested_verify_repo="$(mktemp -d "$RUNNER_TEMP/mrts-lineage.XXXXXX")"',
        'fetch --no-tags "$ALLOWED_NESTED_SUBMODULE_URL" "$current_nested_sha"',
        'fetch --no-tags "$ALLOWED_NESTED_SUBMODULE_URL" "$candidate_nested_sha"',
        'merge-base --is-ancestor "$current_nested_sha" "$candidate_nested_sha"',
        "VALIDATOR SOURCE MUTATION BLOCKED",
        "VALIDATOR WRITE-ROOT CONTRACT BLOCKED",
        "Enforce isolated candidate result after verification",
        "SANDBOX_PREPARE_RESULT: ${{ steps.prepare-readonly-candidate-sandbox.outcome }}",
        "CANDIDATE_RESULT: ${{ steps.run-readonly-candidate-namespace.outcome }}",
        'test "$SANDBOX_PREPARE_RESULT" = success',
        'test "$CANDIDATE_RESULT" = success',
        "git -c core.hooksPath=/dev/null diff --check",
        'git -c core.hooksPath=/dev/null -C "$SUBMODULE_PATH" diff --check',
        "printf 'write_root=%s\\n' \"$write_root\" >> \"$GITHUB_OUTPUT\"",
        "Clean up private read-only candidate guard",
        READONLY_SUBMODULE_CLEANUP_GATE,
        READONLY_SUBMODULE_CLEANUP_CALL,
        "READONLY_SUBMODULE_VALIDATION_SANDBOX_CLEANED",
    )
    for term in required:
        if term not in normalized:
            errors.append(f"missing {term}")

    forbidden = (
        "setfacl",
        "getfacl",
        "unshare",
        "mount ",
        "umount",
        "sudo -n -u modsecurity-validator",
        "env -i",
        "bash --noprofile --norc -ceu",
        'make PYTHON="$PYTHON" BUILD_ROOT=',
        "rm -rf",
        "git status --porcelain --untracked-files=all",
        "grep -v",
        "git reset --hard",
        "git clean",
        "|| true",
        "sudo -n python3 ci/tools/validate-submodule-candidate-state.py",
        "sudo -n git -c core.hooksPath=/dev/null diff --check",
        'sudo -n git -c core.hooksPath=/dev/null -C "$SUBMODULE_PATH" diff --check',
        "chown -R",
        "chmod -R",
        "$SUDO_USER",
        "$USER",
    )
    for term in forbidden:
        if term in validator:
            errors.append(f"workflow must delegate {term!r} exclusively to the namespace helper")

    namespace_count = normalized.count(READONLY_SUBMODULE_NAMESPACE_CALL)
    if namespace_count != 1:
        errors.append("workflow must invoke the namespace helper exactly once")
    if normalized.count("prepare-readonly-submodule-validation-sandbox.py") != 3:
        errors.append("sandbox helper must prepare, verify, and clean exactly once each")
    if normalized.count("umask 077") != 1:
        errors.append("only private guard creation may set the workflow umask")
    if "GH_TOKEN" in validator or "secrets." in validator or "github.token" in validator:
        errors.append("validator job must not receive credentials")
    if "--namespace-parent /tmp" in validator or "--namespace-parent /var/tmp" in validator:
        errors.append("namespace helper must not use a public namespace parent")
    if normalized.count(SUBMODULE_CANDIDATE_BASELINE_CALL) != 1:
        errors.append("candidate validation must capture exactly one immutable Parent baseline")
    if normalized.count(SUBMODULE_CANDIDATE_STATE_CALL) != 2:
        errors.append("candidate validation must run exactly before and after the namespace")

    verification_step = validator.partition(
        "- name: Verify candidate source inventory and external outputs"
    )[2].partition("- name: Enforce isolated candidate result after verification")[0]
    if READONLY_SUBMODULE_VERIFY_GATE not in verification_step:
        errors.append("physical verification must follow a failed candidate but not failed preparation")

    setup_index = normalized.find(READONLY_SUBMODULE_SANDBOX_CALL)
    interpreter_index = normalized.find("Verify Python interpreter contract")
    native_index = normalized.find("Install selected Apache native lifecycle prerequisites")
    native_install_index = normalized.find("sudo apt-get install --no-install-recommends --yes build-essential apache2-dev libmodsecurity-dev")
    baseline_index = normalized.find(SUBMODULE_CANDIDATE_BASELINE_CALL)
    if min(interpreter_index, native_index, native_install_index, baseline_index) < 0 or not (
        interpreter_index < native_index < native_install_index < baseline_index
    ):
        errors.append("Apache native prerequisites must follow the interpreter contract and precede baseline capture")
    contract_index = normalized.find("Validate Framework component-pin data contract")
    dependency_index = normalized.find("Prepare reviewed Python dependency before runtime protection")
    dependency_install_index = normalized.find("python3 ci/tools/install-ci-dependencies.py --ci-toolcache")
    dependency_check_index = normalized.find("python3 -m pip check")
    guard_index = normalized.find("Create private read-only candidate guard")
    if min(contract_index, dependency_index, dependency_install_index, dependency_check_index, guard_index) < 0 or not (
        contract_index < dependency_index < dependency_install_index < dependency_check_index < guard_index < setup_index
    ):
        errors.append("reviewed dependency preparation must follow candidate data validation and precede runtime protection")
    namespace_index = normalized.find(READONLY_SUBMODULE_NAMESPACE_CALL)
    status_index = normalized.find(')" || namespace_status=$?', namespace_index)
    output_index = normalized.find('printf \'%s\\n\' "$namespace_output"', namespace_index)
    failure_index = normalized.find('if [ "$namespace_status" -ne 0 ]; then exit "$namespace_status" fi', namespace_index)
    completion_index = normalized.find('case "$namespace_output" in', namespace_index)
    if min(namespace_index, status_index, output_index, failure_index, completion_index) < 0 or not (
        namespace_index < status_index < output_index < failure_index < completion_index
    ):
        errors.append("namespace output must be printed before preserving a failed candidate status and checking completion")
    verification_index = normalized.find("Verify candidate source inventory and external outputs")
    result_index = normalized.find("Enforce isolated candidate result after verification")
    cleanup_index = normalized.find("Clean up private read-only candidate guard")
    if min(setup_index, namespace_index, verification_index, result_index, cleanup_index) < 0 or not (
        setup_index < namespace_index < verification_index < result_index < cleanup_index
    ):
        errors.append("guard preparation, candidate, verification, result gate, and cleanup must be ordered")
    baseline_index = normalized.find(SUBMODULE_CANDIDATE_BASELINE_CALL)
    checkout_index = normalized.find("checkout --detach")
    first_state_index = normalized.find(SUBMODULE_CANDIDATE_STATE_CALL)
    second_state_index = normalized.find(SUBMODULE_CANDIDATE_STATE_CALL, first_state_index + 1)
    if min(baseline_index, checkout_index, first_state_index, second_state_index) < 0 or not (
        baseline_index < checkout_index < first_state_index < setup_index < second_state_index < result_index
    ):
        errors.append("candidate-state validation must bracket the isolated namespace")
    return errors


def readonly_submodule_sandbox_helper_errors(helper: str) -> list[str]:
    """Return violations of the source-preserving root-side sandbox boundary."""

    errors: list[str] = []
    required = (
        'WRITE_ROOT_PREFIX = "modsecurity-readonly-validation."',
        "def _reject_nested_source_mounts",
        "def _mountinfo_mountpoints",
        "def cleanup_sandbox",
        "def _validate_cleanup_layout",
        "def _open_existing_directory_path",
        "os.O_NOFOLLOW",
        "dir_fd=",
        "source / \".git\"",
        "_reject_mounts_within(write, \"cleanup write root\", include_root=True)",
        "_source_regular_inodes",
        "external output hardlinks a source file",
        "READONLY_SUBMODULE_VALIDATION_SANDBOX_CLEANED",
    )
    for term in required:
        if term not in helper:
            errors.append(f"missing {term}")
    for term in ("_lock_tree", "shutil.", "rmtree", "os.system", "shell=True"):
        if term in helper:
            errors.append(f"source-preserving helper must not use {term!r}")
    try:
        syntax_tree = ast.parse(helper)
    except SyntaxError:
        return [*errors, "source-preserving helper must remain valid Python"]
    function_nodes = {
        node.name: node
        for node in syntax_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    function_text = {
        name: "\n".join(helper.splitlines()[node.lineno - 1 : node.end_lineno])
        for name, node in function_nodes.items()
        if node.end_lineno is not None
    }
    for name in ("prepare_sandbox", "verify_sandbox"):
        body = function_text.get(name, "")
        if not body:
            errors.append(f"missing {name}")
            continue
        nested_mount_index = body.find("_reject_nested_source_mounts(source)")
        inventory_index = body.find("_source_inventory(source)")
        if min(nested_mount_index, inventory_index) < 0 or nested_mount_index > inventory_index:
            errors.append(f"{name} must reject nested source mounts before inventory use")
        for call in ast.walk(function_nodes[name]):
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "os"
                and call.func.attr in {"chown", "chmod", "fchown", "fchmod"}
            ):
                errors.append(f"{name} must not ownership- or mode-mutate the source tree")
    prepare = function_text.get("prepare_sandbox", "")
    if prepare.find("_source_inventory(source)") > prepare.find("_make_external_root(write, identity)"):
        errors.append("prepare must inventory source before creating external output")
    for name, node in function_nodes.items():
        for call in ast.walk(node):
            if not (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "os"
                and call.func.attr in {"chown", "chmod"}
            ):
                continue
            if name != "_make_external_root":
                errors.append(f"{call.func.attr} is only allowed for the private external root")
    cleanup = function_text.get("cleanup_sandbox", "")
    if not cleanup or "_open_existing_directory_path(temporary)" not in cleanup:
        errors.append("cleanup must open the trusted temporary parent by descriptor")
    if not cleanup or "_remove_tree_contents(write_descriptor)" not in cleanup:
        errors.append("cleanup must unlink only descriptor-relative private contents")
    return errors


def readonly_namespace_runner_errors(runner: str) -> list[str]:
    """Return violations of the trusted private mount/PID/chroot launcher contract."""

    errors: list[str] = []
    required = (
        'PROCFS_TARGET = Path("/proc")',
        'JAIL_SOURCE = Path("/source")',
        'JAIL_EXTERNAL = Path("/external")',
        'JAIL_GUARD = Path("/guard")',
        'JAIL_DEV = Path("/dev")',
        "JAIL_RUNTIME_DIRECTORIES =",
        'JAIL_HOSTED_PYTHON_ROOT = Path("/opt/hostedtoolcache/Python")',
        'JAIL_HOSTED_PYTHON_ARCHITECTURE = "x64"',
        'JAIL_COMPILER_ROOT = Path("/usr")',
        'JAIL_C_COMPILER = Path("/usr/bin/gcc")',
        'JAIL_CXX_COMPILER = Path("/usr/bin/g++")',
        "JAIL_RUNTIME_ETC_FILES =",
        'JAIL_FORBIDDEN_PATH_COMPONENTS = ("tmp", "var", "home", "root", "run", "sys")',
        "CLONE_NEWNS | CLONE_NEWPID",
        "MS_NOEXEC = 8",
        "def _reject_nested_source_mounts",
        "_reject_nested_source_mounts(source)",
        "/proc/self/mountinfo",
        "source root contains an unexpected active mount",
        'parser.add_argument("--namespace-parent", required=True)',
        "_validate_namespace_parent(namespace_parent, gid)",
        "namespace_ancestor = namespace_parent.parent",
        "namespace parent must have a trusted sticky ancestor",
        "namespace parent requires a root-owned sticky ancestor",
        "namespace parent must be root:validator mode 0750",
        "namespace parent must be empty before mount layout creation",
        "mount_root = namespace_parent / \"mount-root\"",
        "os.mkdir(path, mode=0o700)",
        "os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)",
        "metadata = os.fstat(descriptor)",
        "not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0",
        "os.fchown(descriptor, 0, validator_gid)",
        "os.fchmod(descriptor, 0o750)",
        "metadata = os.lstat(path)",
        "(0, validator_gid, 0o750)",
        "PR_SET_NO_NEW_PRIVS = 38",
        "if LIBC.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:",
        "_set_no_new_privs()",
        '_mount(None, Path("/"), MS_REC | MS_PRIVATE)',
        '_mount("tmpfs", mount_root, MS_NOSUID | MS_NODEV | MS_NOEXEC, "tmpfs")',
        '_mount("tmpfs", dev_view, MS_NOSUID | MS_NOEXEC, "tmpfs")',
        "_create_jail_device(dev_view / \"null\", 1, 3, 0o666)",
        "_create_jail_device(dev_view / \"urandom\", 1, 9, 0o444)",
        "_mount(str(source), source_view, MS_BIND)",
        "MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV",
        "_mount(str(external), external_view, MS_BIND)",
        "MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV",
        "_verify_mount(source_view, readonly=True)",
        "_verify_mount(external_view, readonly=False)",
        "_mount(None, mount_root, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC)",
        "_verify_mount(mount_root, readonly=True, require_noexec=True)",
        "_hosted_python_runtime_root(python)",
        "_validate_hosted_python_runtime(runtime_root)",
        '_fixed_runtime_executable(JAIL_C_COMPILER, "C compiler")',
        '_fixed_runtime_executable(JAIL_CXX_COMPILER, "C++ compiler")',
        "metadata.st_uid != 0",
        "stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID",
        "relative.parts[1] != JAIL_HOSTED_PYTHON_ARCHITECTURE",
        "hosted_python_root.relative_to(JAIL_ROOT).parts",
        "_bind_readonly(hosted_python_root, hosted_python_target)",
        "os.chdir(jail_root)",
        'os.chroot(".")',
        "_close_unapproved_descriptors({0, 1, 2, proc_ready_write})",
        "_replace_standard_input()",
        "_enter_jail(layout.root)",
        "os.setgroups([]); os.setgid(gid); os.setuid(uid); os.chdir(source)",
        "os.execve(\"/bin/bash\"",
        "READONLY_SUBMODULE_VALIDATION_NAMESPACE_COMPLETE",
        "if _mountinfo_for(mount_root) != before:",
        "os.rmdir(path)",
        'test "$PWD" = "$GITHUB_WORKSPACE"',
        'cap_eff=""; no_new_privs=""',
        "done < /proc/self/status",
        "0000000000000000",
        "NoNewPrivs:",
        "for component in JAIL_FORBIDDEN_PATH_COMPONENTS",
        "for target in /tmp /var /home /root /run /sys /dev/shm",
        "test -c /dev/null; test -c /dev/urandom; test ! -w /dev",
        "validator sees an unexpected device",
        'test -e "$descriptor" || continue',
        "validator retained an inherited descriptor",
        'if /usr/bin/mount -o remount,rw "$GITHUB_WORKSPACE"',
        '"HOME": str(root / "home")',
        '"TMPDIR": str(root / "tmp")',
        '"XDG_CACHE_HOME": str(root / "xdg-cache")',
        '"PIP_CACHE_DIR": str(root / "pip-cache")',
        '"PYTHONPYCACHEPREFIX": str(root / "pycache")',
        '"PYTHONUSERBASE": str(root / "python-user-base")',
        '"PYTHONPATH": str(root / "python-packages")',
        '"CC": str(compiler)',
        '"CXX": str(cxx_compiler)',
        '"GIT_CONFIG_GLOBAL": str(root / "gitconfig")',
        '"GITHUB_ACTIONS": "true"',
        '"BUILD_ROOT": str(root / "build")',
        '"APACHE_C_STANDARDS_OUT": str(root / "build/apache-c-standards")',
        '"VERIFIED_RUN_ROOT": str(root / "verified-run")',
        '"CACHE_ROOT": str(root / "cache")',
        '"VERIFIED_EVIDENCE_ROOT": str(root / "evidence")',
        '"RUNTIME_RUN_ROOT": str(root / "runtime")',
        '"SOURCE_ROOT": str(root / "source")',
        '"MATRIX_ROOT": str(root / "matrix")',
        ".readonly-validator-write-probe",
        ".readonly-validator-runtime-write-probe",
        ".readonly-validator-runtime-directory-probe",
        ".readonly-validator-runtime-rename-probe",
        "/dev/.readonly-validator-device-probe",
        "validator obtained sudo",
        'exec make PYTHON="$PYTHON" quick-check',
        '"$PYTHON" -I -c "import yaml; assert not yaml.__with_libyaml__"',
    )
    for term in required:
        if term not in runner:
            errors.append(f"missing {term}")
    for term in ("tempfile", "os.chmod(", "os.umask(", "BaseException"):
        if term in runner:
            errors.append(f"namespace runner must not use {term!r}")
    if 'exec make PYTHON="$PYTHON" BUILD_ROOT=' in runner:
        errors.append("namespace runner must pass BUILD_ROOT through the environment")
    if "-m pip install" in runner:
        errors.append("namespace runner must consume prepared dependencies without installing packages")
    if 'Path("/opt"),' in runner:
        errors.append("namespace runner must never expose the broad host /opt tree")
    for term in (
        "MS_REC | MS_BIND",
        "MNT_DETACH",
        "shutil.",
        "rmtree",
        "subprocess",
        "shell=True",
        "os.system",
        "secrets.token_hex",
        "awk ",
    ):
        if term in runner:
            errors.append(f"namespace runner must not use {term}")
    if runner.count("_mount(str(source), source_view, MS_BIND)") != 1:
        errors.append("namespace runner must create exactly one non-recursive source bind")
    if runner.count("_mount(str(external), external_view, MS_BIND)") != 1:
        errors.append("namespace runner must create exactly one non-recursive output bind")
    if runner.count("_teardown_jail_layout(layout)") != 1:
        errors.append("namespace runner must synchronously unmount the complete private jail")
    if runner.count('PROCFS_TARGET = Path("/proc")') != 1:
        errors.append("namespace runner must export one immutable literal candidate procfs target")

    try:
        syntax_tree = ast.parse(runner)
    except SyntaxError:
        errors.append("namespace runner must remain valid Python")
        return errors
    functions = {
        node.name: "\n".join(runner.splitlines()[node.lineno - 1 : node.end_lineno])
        for node in syntax_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.end_lineno is not None
    }
    pid1_candidate = functions.get("_run_pid1_candidate", "")
    namespace_child = functions.get("_namespace_child", "")
    configuration = functions.get("_validated_configuration", "")
    jail_builder = functions.get("_build_jail_layout", "")
    descriptor_closer = functions.get("_close_unapproved_descriptors", "")
    if not pid1_candidate:
        errors.append("namespace runner must retain the PID-one candidate helper")
    if not namespace_child:
        errors.append("namespace runner must retain the namespace child launcher")
        return errors
    nested_mount_index = configuration.find("_reject_nested_source_mounts(source)")
    external_index = configuration.find("if external != write_root / \"external\":")
    if not configuration or min(nested_mount_index, external_index) < 0 or nested_mount_index > external_index:
        errors.append("namespace runner must reject nested source mounts before setup")
    if not jail_builder or "_mount(\"tmpfs\", mount_root" not in jail_builder:
        errors.append("namespace runner must construct a private tmpfs jail before candidate execution")
    if (
        "_mount(None, source_view, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)"
        not in jail_builder
    ):
        errors.append("namespace runner must remount the source view read-only inside the jail")
    if (
        "_mount(None, external_view, MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV)"
        not in jail_builder
    ):
        errors.append("namespace runner must retain nodev on the sole writable external view")
    if not descriptor_closer or "os.scandir(\"/proc/self/fd\")" not in descriptor_closer:
        errors.append("namespace runner must close unapproved inherited descriptors through fresh procfs")

    proc_mount = re.compile(
        r'''_mount\(\s*["']proc["']\s*,\s*layout\.proc\s*,\s*'''
        r"MS_RDONLY\s*\|\s*MS_NOSUID\s*\|\s*MS_NODEV\s*\|\s*MS_NOEXEC"
        r'''\s*,\s*["']proc["']\s*\)'''
    )
    proc_match = proc_mount.search(pid1_candidate)
    if proc_match is None:
        errors.append("namespace runner must mount a fresh readonly nosuid nodev noexec procfs inside the jail")
        return errors

    fork_index = namespace_child.find("child = os.fork()")
    layout_index = namespace_child.find("layout = _build_jail_layout(")
    helper_call_index = namespace_child.find("_run_pid1_candidate(", fork_index)
    proc_verify_index = pid1_candidate.find("_verify_procfs(layout.proc)")
    jail_index = pid1_candidate.find("_enter_jail(layout.root)")
    stdin_index = pid1_candidate.find("_replace_standard_input()")
    descriptor_index = pid1_candidate.find("_close_unapproved_descriptors({0, 1, 2, proc_ready_write})")
    readiness_write_index = pid1_candidate.find('os.write(proc_ready_write, b"1")')
    no_new_privs_index = pid1_candidate.find("_set_no_new_privs()")
    candidate_entry_index = pid1_candidate.find("candidate_entry(*candidate_arguments)")
    if min(
        fork_index,
        layout_index,
        helper_call_index,
        proc_verify_index,
        jail_index,
        stdin_index,
        descriptor_index,
        readiness_write_index,
        no_new_privs_index,
        candidate_entry_index,
    ) < 0 or not (
        layout_index < fork_index < helper_call_index
        and proc_match.start() < proc_verify_index < jail_index < stdin_index < descriptor_index
        < readiness_write_index < no_new_privs_index < candidate_entry_index
    ):
        errors.append("jail, descriptor closure, readiness, no_new_privs, and candidate order is unsafe")
    wait_index = namespace_child.find("os.waitpid(child, 0)")
    teardown_index = namespace_child.find("_teardown_jail_layout(layout)")
    readiness_read_index = namespace_child.find('proc_ready = os.read(proc_ready_read, 1) == b"1"')
    if min(readiness_read_index, wait_index, teardown_index) < 0 or not (
        readiness_read_index < wait_index < teardown_index
    ):
        errors.append("namespace runner must wait for PID one before tearing down the private jail")
    return errors


EXPECTED_WRITE_PERMISSIONS = {
    ("run-trusted-lighttpd-namespace-dispatch.yml", "report-trusted-lighttpd-namespace"): {
        "statuses": "write",
    },
    ("cleanup-artifacts.yml", "cleanup-artifacts"): {"actions": "write"},
    ("test-full-smoke-sequential.yml", "cleanup-artifacts"): {"actions": "write"},
    ("update-go-version.yml", "create-go-update-pr"): {
        "contents": "write",
        "pull-requests": "write",
    },
    ("ci-security-codeql.yml", "actions"): {
        "contents": "read",
        "security-events": "write",
    },
    ("ci-security-codeql.yml", "envoy-go"): {
        "contents": "read",
        "security-events": "write",
    },
    ("ci-security-codeql.yml", "traefik-go"): {
        "contents": "read",
        "security-events": "write",
    },
    ("ci-security-codeql.yml", "bounded-c-cpp"): {
        "contents": "read",
        "security-events": "write",
    },
    ("ci-security-osv.yml", "pull-request-diff"): {
        "contents": "read",
        "security-events": "write",
    },
    ("ci-security-scorecard.yml", "default-branch"): {
        "contents": "read",
        "security-events": "write",
    },
}


def mapping_after(lines: list[str], index: int, indent: int) -> dict[str, str]:
    """Return the scalar mapping immediately below a known indentation level."""

    mapping: dict[str, str] = {}
    child_prefix = " " * (indent + 2)
    for line in lines[index + 1 :]:
        if not line.strip():
            continue
        if not line.startswith(child_prefix):
            break
        match = re.match(rf"^{re.escape(child_prefix)}(?P<key>[A-Za-z0-9_-]+):\s*(?P<value>[^\s#]+)", line)
        if match is None:
            continue
        mapping[match.group("key")] = match.group("value")
    return mapping


def top_level_permissions(text: str) -> dict[str, str]:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line == "permissions: {}":
            return {}
        if line == "permissions:":
            return mapping_after(lines, index, 0)
    raise AssertionError("workflow has no top-level permissions mapping")


def job_blocks(text: str) -> dict[str, str]:
    """Split the top-level jobs mapping without adding a YAML dependency."""

    lines = text.splitlines()
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    in_jobs = False
    for line in lines:
        if line == "jobs:":
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if line and not line.startswith(" "):
            break
        match = JOB_HEADER.match(line)
        if match:
            current = match.group("name")
            blocks[current] = [line]
        elif current is not None:
            blocks[current].append(line)
    return {name: "\n".join(block) for name, block in blocks.items()}


def job_permissions(job: str) -> dict[str, str]:
    lines = job.splitlines()
    for index, line in enumerate(lines):
        if line == "    permissions: {}":
            return {}
        if line == "    permissions:":
            return mapping_after(lines, index, 4)
    return {}


def job_has_explicit_permissions(job: str) -> bool:
    """Return whether the job declares its token permissions explicitly."""

    return any(
        line in {"    permissions:", "    permissions: {}"}
        for line in job.splitlines()
    )


def submodule_publisher_app_token_inputs(text: str) -> dict[str, str]:
    """Return the complete App-token input mapping for the submodule publisher."""

    publisher = job_blocks(text).get("create-submodule-update-pr", "")
    match = re.search(
        r"^      - name: Mint repository-limited submodule publisher App token\n"
        r"        id: publisher_app_token\n"
        rf"        uses: {re.escape(SUBMODULE_PUBLISHER_APP_TOKEN_ACTION)}@[^\n]+\n"
        r"        with:\n(?P<inputs>(?:          [A-Za-z0-9-]+: [^\n]+\n)+)",
        publisher,
        re.MULTILINE,
    )
    if match is None:
        return {}
    return dict(
        re.findall(
            r"^          ([A-Za-z0-9-]+): ([^\n]+)$",
            match.group("inputs"),
            re.MULTILINE,
        )
    )


def submodule_publisher_token_errors(text: str) -> list[str]:
    """Return violations of the least-privilege submodule publisher token boundary."""

    errors: list[str] = []
    jobs = job_blocks(text)
    required_jobs = {
        "resolve-submodule-update",
        "validate-submodule-update",
        "create-submodule-update-pr",
        "report-submodule-update-outcome",
    }
    if not required_jobs.issubset(jobs):
        return ["submodule publisher token contract jobs are missing"]

    publisher = jobs["create-submodule-update-pr"]
    if job_permissions(publisher) != {"contents": "read"}:
        errors.append("publisher ambient permissions must remain contents-read only")
    if submodule_publisher_app_token_inputs(text) != SUBMODULE_PUBLISHER_APP_TOKEN_INPUTS:
        errors.append("publisher App-token inputs must be complete, exact, and repository-limited")
    if publisher.count(f"{SUBMODULE_PUBLISHER_APP_TOKEN_ACTION}@") != 1:
        errors.append("publisher must mint exactly one App token")
    if publisher.count("id: publisher_app_token") != 1:
        errors.append("publisher App-token step identity must be unique")
    if publisher.count("${{ vars.WORKFLOW_UPDATER_APP_CLIENT_ID }}") != 2:
        errors.append("publisher must preflight and mint with the one expected App client ID")
    if publisher.count("${{ secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY }}") != 2:
        errors.append("publisher must preflight and mint with the one expected App private key")
    if publisher.count("secrets.") != 2:
        errors.append("publisher must not receive any secret beyond the expected App private key")
    if re.search(r"\bsecrets\s*\[", publisher):
        errors.append("publisher must not use bracket-indexed secret access")
    if publisher.count(SUBMODULE_PUBLISHER_APP_TOKEN_OUTPUT) != 1:
        errors.append("publisher must use the minted token exactly once")
    if f"GH_TOKEN: {SUBMODULE_PUBLISHER_APP_TOKEN_OUTPUT}" not in publisher:
        errors.append("publisher must authenticate GitHub CLI and Git with the minted App token")
    if "${{ github.token }}" in publisher:
        errors.append("publisher must not fall back to the ambient GitHub token")

    for job_name in required_jobs - {"create-submodule-update-pr"}:
        job = jobs[job_name]
        if any(
            marker in job
            for marker in (
                "secrets.",
                "WORKFLOW_UPDATER_APP_",
                "publisher_app_token",
                SUBMODULE_PUBLISHER_APP_TOKEN_ACTION,
            )
        ):
            errors.append(f"{job_name} must not receive the publisher App credential")
    return errors


def job_if_expression(job: str) -> str | None:
    """Return the unique job-level ``if`` expression without YAML evaluation."""

    lines = job.splitlines()
    expressions: list[str] = []
    for index, line in enumerate(lines):
        if not line.startswith("    if:"):
            continue
        value = line.removeprefix("    if:").strip()
        if value in {">", ">-", "|", "|-"}:
            continuation: list[str] = []
            for candidate in lines[index + 1 :]:
                if candidate.startswith("      "):
                    continuation.append(candidate.strip())
                    continue
                if candidate.strip():
                    break
            value = " ".join(continuation)
        expressions.append(value)
    if len(expressions) != 1:
        return None
    expression = expressions[0]
    if expression.startswith("${{") and expression.endswith("}}"):
        expression = expression.removeprefix("${{").removesuffix("}}").strip()
    return " ".join(expression.split())


def update_submodule_validate_only_errors(text: str) -> list[str]:
    """Return violations of the manual non-publishing validation contract."""

    errors: list[str] = []
    trigger = re.search(r"(?ms)^on:\n(?P<body>.*?)(?=^permissions:)", text)
    if trigger is None or re.findall(
        r"(?m)^  ([A-Za-z_][A-Za-z0-9_-]*):", trigger.group("body")
    ) != ["workflow_dispatch"]:
        errors.append("submodule updater must have only workflow_dispatch")
    if text.count(SUBMODULE_VALIDATE_ONLY_INPUT) != 1:
        errors.append("validate_only must be one exact optional-false boolean input")
    if text.count(SUBMODULE_VALIDATE_ONLY_PROTECTED_FLAG) != 4:
        errors.append("protected-master validation must have four exact ref-protection checks")
    if text.count(SUBMODULE_VALIDATE_ONLY_BRANCH) != 4:
        errors.append("repair-branch validation admission must have four exact branch checks")
    if SUBMODULE_VALIDATE_ONLY_RETIRED_PR280_BRANCH in text:
        errors.append("retired PR #280 validation-only branch must not be admitted")

    jobs = job_blocks(text)
    required_jobs = {
        "resolve-submodule-update",
        "validate-submodule-update",
        "create-submodule-update-pr",
        "report-submodule-update-outcome",
    }
    if not required_jobs.issubset(jobs):
        return errors + ["validate_only contract jobs are missing"]

    resolver = jobs["resolve-submodule-update"]
    validator = jobs["validate-submodule-update"]
    publisher = jobs["create-submodule-update-pr"]
    outcome = jobs["report-submodule-update-outcome"]
    normalized_resolver = normalize_shell_script(resolver)
    normalized_outcome = normalize_shell_script(outcome)

    if job_if_expression(resolver) != SUBMODULE_RESOLVER_GATE:
        errors.append("resolver must allow only same-repository master or manual validate_only")
    if job_if_expression(validator) != SUBMODULE_VALIDATOR_GATE:
        errors.append("validator must retain its successful changed-candidate gate")
    if job_if_expression(publisher) != SUBMODULE_PUBLISHER_GATE:
        errors.append("publisher must be disabled by the resolver-derived validate_only flag")
    if job_if_expression(outcome) != "always()":
        errors.append("outcome reporter must inspect every terminal job state")

    checkout_contracts = (
        ("resolver", resolver, "Checkout Parent metadata"),
        ("validator", validator, "Checkout candidate for read-only validation"),
    )
    for name, job, step_name in checkout_contracts:
        checkout_steps = checkout_step_blocks(job)
        if (
            len(checkout_steps) != 1
            or f"- name: {step_name}" not in checkout_steps[0]
            or checkout_steps[0].count(SUBMODULE_VALIDATE_ONLY_CHECKOUT_REF) != 1
        ):
            errors.append(
                f"{name} named checkout must use the dispatched SHA only for validate_only"
            )
    if SUBMODULE_VALIDATE_ONLY_CHECKOUT_REF in publisher:
        errors.append("publisher must never check out the dispatched validate_only SHA")
    if "ref: ${{ github.event.repository.default_branch }}" not in publisher:
        errors.append("publisher must retain the default-branch checkout")

    activation = (
        "validation_only=false "
        f'if [ "${{{{ {SUBMODULE_VALIDATE_ONLY_MANUAL_PREDICATE} }}}}" = true ]; then '
        "validation_only=true fi"
    )
    force_changed = 'if [ "$validation_only" = true ]; then changed=true fi'
    if activation not in normalized_resolver:
        errors.append("resolver must derive validation_only only from the manual boolean input")
    if normalized_resolver.count(force_changed) != 1:
        errors.append("resolver must force changed exactly once and only inside validation_only")
    if normalized_resolver.count("changed=true") != 2:
        errors.append("changed may be true only for a real update or validate_only")
    if re.findall(r"\bchanged=(?:false|true)\b", normalized_resolver) != [
        "changed=false",
        "changed=true",
        "changed=true",
    ]:
        errors.append("validation_only must be the final changed assignment before outputs")
    if (
        activation in normalized_resolver
        and force_changed in normalized_resolver
        and normalized_resolver.index(activation) >= normalized_resolver.index(force_changed)
    ):
        errors.append("validation_only activation must precede its changed override")
    if resolver.count("validation_only: ${{ steps.resolve.outputs.validation_only }}") != 1:
        errors.append("resolver must expose one validation_only job output")
    if normalized_resolver.count(
        "printf 'validation_only=%s\\n' \"$validation_only\""
    ) != 1:
        errors.append("resolver must publish one validation_only step output")

    if job_permissions(resolver) != {"contents": "read"}:
        errors.append("resolver permissions must remain contents-read only")
    if job_permissions(validator) != {"contents": "read"}:
        errors.append("validator permissions must remain contents-read only")
    if job_permissions(publisher) != {"contents": "read"}:
        errors.append("publisher ambient permissions must remain contents-read only")
    if job_permissions(outcome) != {"contents": "read"}:
        errors.append("outcome reporter permissions must remain contents-read only")
    if any(term in resolver or term in validator for term in ("GH_TOKEN", "secrets.", "github.token")):
        errors.append("resolver and validator must not receive publishing credentials")
    if any(term in publisher for term in ("gh pr merge", "--auto", "enablePullRequestAutoMerge")):
        errors.append("publisher must not enable or perform auto-merge")

    validation_only_case = 'case "$VALIDATION_ONLY" in'
    changed_case = 'case "$CHANGED" in'
    validation_only_success = (
        'if [ "$CHANGED" != "true" ] || [ "$VALIDATOR_RESULT" != "success" ] || '
        '[ "$PUBLISHER_RESULT" != "skipped" ]; then'
    )
    normal_update_success = (
        'if [ "$VALIDATOR_RESULT" != "success" ] || '
        '[ "$PUBLISHER_RESULT" != "success" ]; then'
    )
    if outcome.count(
        "VALIDATION_ONLY: ${{ needs.resolve-submodule-update.outputs.validation_only }}"
    ) != 1:
        errors.append("outcome reporter must consume one resolver-derived validation_only output")
    if normalized_outcome.count(validation_only_case) != 1:
        errors.append("outcome reporter must have one validation_only state case")
    if normalized_outcome.count(changed_case) != 1:
        errors.append("outcome reporter must retain one normal changed state case")
    if validation_only_case in normalized_outcome and changed_case in normalized_outcome:
        validation_only_section = normalized_outcome.partition(validation_only_case)[2].partition(
            changed_case
        )[0]
        if validation_only_success not in validation_only_section:
            errors.append("validate_only success requires changed, validator success, and publisher skip")
        if "exit 0" not in validation_only_section:
            errors.append("successful validate_only reporting must exit before normal publishing checks")
        if normalized_outcome.index(validation_only_case) >= normalized_outcome.index(changed_case):
            errors.append("validate_only state must be handled before the normal changed state")
    if normalized_outcome.count(normal_update_success) != 1:
        errors.append("normal changed updates must still require validator and publisher success")
    return errors


def has_exact_master_only_gate(job: str, extra_terms: set[str]) -> bool:
    """Require a conjunction of the fixed master gate and approved job clauses."""

    expression = job_if_expression(job)
    if expression is None:
        return False
    terms = {term.strip() for term in expression.split("&&")}
    return terms == PROTECTED_NGINX_BROKER_CALLER_MASTER_GATE_TERMS | extra_terms


def job_direct_key_count(job: str, key: str) -> int:
    """Count direct job mapping keys, including malformed duplicate keys."""

    return sum(line.startswith(f"    {key}:") for line in job.splitlines())


def job_with_keys(job: str) -> list[str] | None:
    """Return direct ``with`` keys only when the job has one such mapping."""

    lines = job.splitlines()
    with_indexes = [index for index, line in enumerate(lines) if line.startswith("    with:")]
    if len(with_indexes) != 1:
        return None
    keys: list[str] = []
    for line in lines[with_indexes[0] + 1 :]:
        if not line.strip():
            continue
        if len(line) - len(line.lstrip()) <= 4:
            break
        match = re.match(r"^      (?P<key>[A-Za-z_][A-Za-z0-9_-]*):", line)
        if match is not None:
            keys.append(match.group("key"))
    return keys


def checkout_step_blocks(text: str) -> list[str]:
    """Return each checkout step through the next step at the same indent."""

    lines = text.splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        if "uses: actions/checkout@" not in line:
            continue
        start = index
        while start > 0 and STEP_HEADER.match(lines[start]) is None:
            start -= 1
        step_match = STEP_HEADER.match(lines[start])
        if step_match is None:
            raise AssertionError(f"checkout is not in a workflow step: {line}")
        step_indent = len(step_match.group("indent"))
        end = len(lines)
        for candidate in range(start + 1, len(lines)):
            candidate_match = STEP_HEADER.match(lines[candidate])
            if candidate_match and len(candidate_match.group("indent")) <= step_indent:
                end = candidate
                break
        blocks.append("\n".join(lines[start:end]))
    return blocks


def fixture_violations(text: str) -> set[str]:
    """Model the policy boundary exercised by the safe/unsafe fixtures."""

    violations: set[str] = set()
    if "pull_request_target:" in text:
        violations.add("pull_request_target")
    if top_level_permissions(text) != {"contents": "read"}:
        violations.add("top_level_permissions")
    if "secrets." in text:
        violations.add("secret_reference")
    for job in job_blocks(text).values():
        permissions = job_permissions(job)
        checkout_steps = checkout_step_blocks(job)
        if any("persist-credentials: false" not in step for step in checkout_steps):
            violations.add("persisted_credentials")
        if (
            any(value == "write" for value in permissions.values())
            and "submodules: recursive" in job
            and "make quick-check" in job
        ):
            violations.add("privileged_submodule_execution")
    return violations


def yaml_security_errors(text: str) -> list[str]:
    """Reject YAML indirection without treating block-scalar code as YAML."""

    errors: list[str] = []
    key_token_seen = False
    try:
        for token in yaml.scan(text):
            line_number = token.start_mark.line + 1
            if isinstance(token, KeyToken):
                key_token_seen = True
                continue
            if isinstance(token, AnchorToken):
                errors.append(f"line {line_number}: anchor")
            elif isinstance(token, AliasToken):
                errors.append(f"line {line_number}: alias")
            elif isinstance(token, TagToken):
                errors.append(f"line {line_number}: tag")
            elif (
                key_token_seen
                and isinstance(token, ScalarToken)
                and token.style is None
                and token.value == "<<"
            ):
                errors.append(f"line {line_number}: merge key")
            if not isinstance(token, KeyToken):
                key_token_seen = False
    except yaml.YAMLError as exc:
        line_number = getattr(getattr(exc, "problem_mark", None), "line", 0) + 1
        errors.append(f"line {line_number}: malformed YAML")
    return errors


def protected_nginx_broker_caller_errors(text: str) -> list[str]:
    """Return exact trust-contract violations for the protected dispatch caller."""

    errors: list[str] = []
    if not text.startswith("name: Protected NGINX Root Broker Lifecycle\n"):
        errors.append("caller workflow name")
    trigger_match = re.search(r"(?ms)^on:\n(?P<body>.*?)(?=^permissions:(?: \{\})?\n)", text)
    if trigger_match is None:
        errors.append("caller trigger section")
        trigger_body = ""
    else:
        trigger_body = trigger_match.group("body")
        triggers = re.findall(r"(?m)^  ([A-Za-z_][A-Za-z0-9_-]*):", trigger_body)
        if triggers != ["workflow_dispatch"]:
            errors.append("caller must have only workflow_dispatch")
        inputs = re.findall(r"(?m)^      ([A-Za-z_][A-Za-z0-9_-]*):", trigger_body)
        if inputs != ["parent_head_sha"]:
            errors.append("caller must expose only parent_head_sha")
        if "        required: true" not in trigger_body or "        type: string" not in trigger_body:
            errors.append("caller parent_head_sha must be required string")
    for forbidden in (
        "pull_request:",
        "pull_request_target:",
        "push:",
        "workflow_call:",
        "repository_dispatch:",
        "workflow_run:",
    ):
        if forbidden in text:
            errors.append(f"forbidden trigger {forbidden}")
    try:
        if top_level_permissions(text) != {}:
            errors.append("caller top-level permissions")
    except AssertionError:
        errors.append("caller top-level permissions")
    if (
        "  group: protected-nginx-root-broker-caller" not in text
        or "  cancel-in-progress: false" not in text
    ):
        errors.append("caller non-cancelling concurrency")
    expected_jobs = {
        "prepare-manifests",
        "run-no-crs-broker",
        "run-with-crs-broker",
        "verify-evidence",
        "result",
    }
    jobs = job_blocks(text)
    if set(jobs) != expected_jobs:
        errors.append("caller job inventory")
    expected_gate_extras = {
        "prepare-manifests": set(),
        "run-no-crs-broker": {"needs.prepare-manifests.result == 'success'"},
        "run-with-crs-broker": {"needs.prepare-manifests.result == 'success'"},
        "verify-evidence": {
            "always()",
            "needs.prepare-manifests.result == 'success'",
            "needs.run-no-crs-broker.result == 'success'",
            "needs.run-with-crs-broker.result == 'success'",
        },
        "result": {"always()"},
    }
    for name, job in jobs.items():
        if job_permissions(job) != {"contents": "read"}:
            errors.append(f"caller job permissions {name}")
        if not has_exact_master_only_gate(job, expected_gate_extras.get(name, set())):
            errors.append(f"caller master-only gate {name}")
    if "matrix:" in text or "strategy:" in text:
        errors.append("caller must not use a dynamic matrix")
    protected_calls = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith("uses: Easton97-Jens/ModSecurity-conector/.github/workflows/")
    ]
    if protected_calls != [
        f"uses: {PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE}",
        f"uses: {PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE}",
    ]:
        errors.append("caller immutable protected broker reference")
    required_no_crs = (
        "      caller_manifest_artifact: protected-nginx-caller-${{ github.run_id }}-${{ github.run_attempt }}-no-crs",
        "      parent_head_sha: ${{ inputs.parent_head_sha }}",
        f"      framework_sha: {PROTECTED_NGINX_BROKER_FRAMEWORK_SHA}",
        f"      protected_broker_sha: {PROTECTED_NGINX_BROKER_SHA}",
        "      matrix_variant: no-crs",
        "      run_id: protected-nginx-root-${{ github.run_id }}-${{ github.run_attempt }}-no-crs",
    )
    required_with_crs = tuple(item.replace("no-crs", "with-crs") for item in required_no_crs)
    required_with_crs = tuple(
        item.replace("matrix_variant: with-crs", "matrix_variant: with-crs")
        for item in required_with_crs
    )
    expected_broker_input_keys = [
        "caller_manifest_artifact",
        "parent_head_sha",
        "framework_sha",
        "protected_broker_sha",
        "matrix_variant",
        "run_id",
    ]
    for job_name, requirements in (
        ("run-no-crs-broker", required_no_crs),
        ("run-with-crs-broker", required_with_crs),
    ):
        job = jobs.get(job_name, "")
        if job_direct_key_count(job, "uses") != 1:
            errors.append(f"caller immutable protected broker reference {job_name}")
        if job_direct_key_count(job, "with") != 1 or job_with_keys(job) != expected_broker_input_keys:
            errors.append(f"caller exact broker input keys {job_name}")
        for required in requirements:
            if required not in job:
                errors.append(f"caller fixed broker input {job_name} {required}")
    if "policy_profile:" in trigger_body or "matrix_variant:" in trigger_body:
        errors.append("caller exposes a dynamic profile or variant")
    prepare = jobs.get("prepare-manifests", "")
    if "create-manifests" not in prepare or '--target-sha "$TARGET_PARENT_SHA"' not in prepare:
        errors.append("caller manifest preparation")
    if (
        "ref: ${{ github.sha }}" not in prepare
        or 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' not in prepare
        or "persist-credentials: false" not in prepare
    ):
        errors.append("caller checkout identity")
    if "--output-root" in prepare:
        errors.append("caller manifest path must be derived from the trusted runner temporary directory")
    if prepare.count("caller-manifest.json") != 2:
        errors.append("caller must upload exactly two single-file manifests")
    if any(
        pattern in text
        for pattern in (
            "uses: ./",
            "@master",
            "@fix/",
            "secrets.",
            "${{ secrets.",
            "sudo",
            "git checkout \"$TARGET_PARENT_SHA\"",
            "git checkout '${TARGET_PARENT_SHA}'",
            "ref: ${{ inputs.parent_head_sha }}",
            "python3 \"$TARGET_PARENT_SHA\"",
            "source \"$TARGET_PARENT_SHA\"",
            "make $TARGET_PARENT_SHA",
        )
    ):
        errors.append("caller target-code or privilege boundary")
    evidence = jobs.get("verify-evidence", "")
    if (
        "verify-evidence" not in evidence
        or "Download no-CRS broker evidence" not in evidence
        or "Download OWASP CRS broker evidence" not in evidence
    ):
        errors.append("caller evidence readback")
    if "--no-crs-directory" in evidence or "--with-crs-directory" in evidence:
        errors.append("caller evidence paths must be derived from the trusted runner temporary directory")
    result = jobs.get("result", "")
    for required in (
        "always()",
        '"$PREPARE_RESULT" != success',
        '"$NO_CRS_RESULT" != success',
        '"$WITH_CRS_RESULT" != success',
        '"$EVIDENCE_RESULT" != success',
        "exit 1",
    ):
        if required not in result:
            errors.append("caller fail-closed result")
            break
    return errors


def go_module_requirements(text: str) -> dict[str, tuple[int, int, int]]:
    """Return stable semantic versions declared in Go require directives."""

    requirements: dict[str, tuple[int, int, int]] = {}
    in_require_block = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line == "require (":
            in_require_block = True
            continue
        if in_require_block and line == ")":
            in_require_block = False
            continue
        if in_require_block:
            candidate = line
        elif line.startswith("require "):
            candidate = line.removeprefix("require ").strip()
        else:
            continue
        match = GO_MODULE_REQUIREMENT.fullmatch(candidate)
        if match is None:
            continue
        requirements[match.group("module")] = tuple(
            int(match.group(part)) for part in ("major", "minor", "patch")
        )
    return requirements


def locked_action_pins() -> set[str]:
    """Return immutable Action SHAs from the current reviewed lock."""

    raw = yaml.safe_load(LOCK_PATH.read_text(encoding="utf-8"))
    actions = raw.get("pinned_actions", {}) if isinstance(raw, dict) else {}
    if not isinstance(actions, dict):
        raise AssertionError("workflow Action lock has no pinned_actions mapping")
    pins = {
        record.get("commit_sha")
        for record in actions.values()
        if isinstance(record, dict) and isinstance(record.get("commit_sha"), str)
    }
    if not pins or any(not re.fullmatch(r"[a-f0-9]{40}", pin) for pin in pins):
        raise AssertionError("workflow Action lock contains an invalid immutable pin")
    return pins


def locked_action_pin(name: str) -> str:
    """Return one exact Action reference prefix bound to the reviewed lock."""

    raw = yaml.safe_load(LOCK_PATH.read_text(encoding="utf-8"))
    actions = raw.get("pinned_actions", {}) if isinstance(raw, dict) else {}
    record = actions.get(name) if isinstance(actions, dict) else None
    if not isinstance(record, dict) or not isinstance(record.get("commit_sha"), str):
        raise AssertionError(f"workflow Action lock has no immutable pin for {name}")
    return f"{name}@{record['commit_sha']}"


def normalize_locked_action_pins(text: str) -> str:
    """Canonicalize only reviewed Action pins before a structural digest check."""

    pins = locked_action_pins()

    def replace(match: re.Match[str]) -> str:
        if match.group("sha") not in pins:
            return match.group(0)
        return f"{match.group('prefix')}<locked-action> # <locked-version>"

    return LOCKED_ACTION_USE.sub(replace, text)


def locked_action_reference_with_version(name: str) -> str:
    """Bind runtime workflow assertions to the reviewed lock SHA and release tag."""
    raw = yaml.safe_load(LOCK_PATH.read_text(encoding="utf-8"))
    record = raw["pinned_actions"][name]
    if not isinstance(record.get("version"), str):
        raise AssertionError(f"workflow Action lock has no release version for {name}")
    return f"{locked_action_pin(name)} # {record['version']}"


def sonar_pr_secret_errors(text: str) -> list[str]:
    """Admit only the fixed same-repository scanner's step-local secret."""
    try:
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        jobs = workflow["jobs"]
        job = jobs["analysis"]
        steps = job["steps"]
        scanner_steps = [step for step in steps if "SONAR_TOKEN" in step.get("env", {})]
        scanner = scanner_steps[0]
        strategy = job["strategy"]
    except (KeyError, IndexError, TypeError, yaml.YAMLError):
        return ["missing fixed Sonar scanner structure"]
    expected_guard = (
        "github.repository == 'Easton97-Jens/ModSecurity-conector' && "
        "(github.event_name == 'push' || "
        "github.event.pull_request.head.repo.full_name == github.repository)"
    )
    expected_variants = [
        {"cpp": "17", "project": "Easton97-Jens_ModSecurity-conector", "advisory": "false", "branch_args": ""},
        {"cpp": "20", "project": "Easton97-Jens_ModSecurity-conector_cpp20_advisory", "advisory": "true", "branch_args": "-Dsonar.branch.name=master"},
        {"cpp": "23", "project": "Easton97-Jens_ModSecurity-conector_cpp23_advisory", "advisory": "true", "branch_args": "-Dsonar.branch.name=master"},
    ]
    checks = {
        "only the fixed analysis job is permitted": set(jobs) == {"analysis"},
        "same-repository guard must match exactly": " ".join(job.get("if", "").split()) == expected_guard,
        "workflow permissions must default deny": workflow.get("permissions") == {},
        "scanner job must be read only": job.get("permissions") == {"contents": "read"},
        "standard/project/gating matrix must match exactly": strategy.get("matrix", {}).get("include") == expected_variants,
        "only higher standards may be advisory": job.get("continue-on-error") == "${{ matrix.advisory }}",
        "all standard analyses must finish independently": strategy.get("fail-fast") == "false",
        "only push/master and ordinary pull requests are permitted": workflow.get("on") == {
            "push": {"branches": ["master"]}, "pull_request": "",
        },
        "secret must be on one immutable scanner action": (
            len(scanner_steps) == 1
            and scanner.get("uses") == locked_action_pin("SonarSource/sonarqube-scan-action")
            and "run" not in scanner
        ),
        "scanner secret mapping must be exact": scanner.get("env") == {
            "SONAR_TOKEN": "${{ secrets.SONAR_TOKEN }}",
        },
        "no other secret expression is permitted": (
            text.count("${{ secrets.SONAR_TOKEN }}") == 1
            and re.search(r"\bsecrets\b", text.replace("${{ secrets.SONAR_TOKEN }}", "", 1), re.IGNORECASE) is None
        ),
        "workflow and job environments must not receive the token": all(
            "SONAR_TOKEN" not in item.get("env", {}) for item in (workflow, job)
        ),
    }
    return [message for message, valid in checks.items() if not valid]


def sonar_native_pr_secret_errors(text: str) -> list[str]:
    """Admit only the complete reviewed twelve-project native scanner workflow.

    The structural digest closes every source-changing step, script, argument,
    default, environment and matrix field. Only exact canonical Action identity
    and release updates are normalized; arbitrary pinned actions are rejected.
    """
    try:
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        sdk, native = workflow["jobs"]["sdk"], workflow["jobs"]["native"]
        scanner = next(step for step in native["steps"] if step.get("id") == "scan")
        allowed_actions = {"actions/checkout", "actions/setup-python", "actions/setup-go",
                           "actions/upload-artifact", "actions/download-artifact",
                           "SonarSource/sonarqube-scan-action"}
        for match in LOCKED_ACTION_USE.finditer(text):
            action = match.group("prefix").split("uses:", 1)[1].strip().removesuffix("@")
            if (action not in allowed_actions
                    or match.group(0) != "uses: " + locked_action_reference_with_version(action)):
                return ["native workflow Action differs from its exact canonical source/lock identity"]
        guard = ("github.repository == 'Easton97-Jens/ModSecurity-conector' && "
                 "(github.event_name == 'push' || "
                 "github.event.pull_request.head.repo.full_name == github.repository)")
        if any(" ".join(job.get("if", "").split()) != guard for job in (sdk, native)):
            return ["native workflow must restrict both jobs to the exact same-repository guard"]
        if (scanner["env"] != {"SONAR_TOKEN": "${{ secrets.SONAR_TOKEN }}", "SONAR_SCANNER_JAVA_OPTS": "-Xmx2g",
                               "SONAR_USER_HOME": "${{ runner.temp }}/native-sonar-cache"}
                or text.count("${{ secrets.SONAR_TOKEN }}") != 1
                or re.search(r"\bsecrets\b", text.replace("${{ secrets.SONAR_TOKEN }}", ""), re.IGNORECASE)):
            return ["native workflow credentials must exist only on the exact pinned scanner step"]
        if sha256(normalize_locked_action_pins(text).encode()).hexdigest() != SONAR_NATIVE_WORKFLOW_NORMALIZED_SHA256:
            return ["native workflow differs from its closed reviewed source/steps/env/matrix/SCM contract"]
    except (KeyError, StopIteration, TypeError, AssertionError, yaml.YAMLError):
        return ["native workflow is missing its closed reviewed structure"]
    return []


class CiSecurityWorkflowTest(unittest.TestCase):
    def workflow(self, name: str) -> str:
        return read_connector_workflow(WORKFLOWS / name)

    def workflow_paths(self) -> list[Path]:
        return sorted({path for pattern in WORKFLOW_PATTERNS for path in WORKFLOWS.glob(pattern)})

    def jobs(self, name: str) -> dict[str, str]:
        return job_blocks(self.workflow(name))

    def test_all_remote_actions_are_immutable_sha_pins(self) -> None:
        lock_data = yaml.safe_load(LOCK_PATH.read_text(encoding="utf-8"))
        locked_actions = (
            lock_data.get("pinned_actions", {}) if isinstance(lock_data, dict) else {}
        )
        self.assertIsInstance(locked_actions, dict)
        for path in self.workflow_paths():
            for line in path.read_text(encoding="utf-8").splitlines():
                if "uses:" not in line or "@" not in line or "./" in line:
                    continue
                reference = line.split("uses:", 1)[1].strip()
                if reference.startswith(
                    "Easton97-Jens/ModSecurity-conector/.github/workflows/"
                ):
                    self.assertEqual(path.name, PROTECTED_NGINX_BROKER_CALLER_WORKFLOW)
                    self.assertEqual(reference, PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE)
                    continue
                self.assertRegex(reference, SHA_PIN, f"{path}: {line}")
                action_with_suffix, pinned_sha = reference.split("@", 1)
                action_name = "/".join(action_with_suffix.split("/")[:2])
                record = locked_actions.get(action_name)
                self.assertIsInstance(record, dict, f"{path}: {line}")
                self.assertEqual(
                    pinned_sha.split()[0],
                    record.get("commit_sha"),
                    f"{path}: {line}",
                )

    def test_workflow_and_lock_yaml_reject_forbidden_indirection(self) -> None:
        unsafe = """\
defaults: &unsafe
  run:
    shell: bash
jobs:
  reuse:
    <<: *unsafe
    value: !unsafe value
"""
        self.assertEqual(
            yaml_security_errors(unsafe),
            ["line 1: anchor", "line 6: merge key", "line 6: alias", "line 7: tag"],
        )
        checked_paths = [*self.workflow_paths(), source_path('ci/tooling/security-tools.lock.yml', root=ROOT)]
        for path in checked_paths:
            with self.subTest(path=path):
                self.assertEqual(yaml_security_errors(path.read_text(encoding="utf-8")), [])

    def test_secret_scan_uses_exact_pr_range_and_advisory_history(self) -> None:
        text = self.workflow("ci-security-secrets.yml")
        self.assertIn("github.event.pull_request.base.sha", text)
        self.assertIn("github.event.pull_request.head.sha", text)
        self.assertIn('git merge-base "$BASE_SHA" "$HEAD_SHA"', text)
        self.assertIn("--redact=100", text)
        self.assertIn("continue-on-error: true", text)

    def test_osv_uses_the_pr_head_not_merge_sha(self) -> None:
        text = self.workflow("ci-security-osv.yml")
        self.assertIn("OSV_HEAD_SHA: ${{ github.event.pull_request.head.sha }}", text)
        self.assertNotIn("OSV_HEAD_SHA: ${{ github.sha }}", text)
        self.assertIn("old-results.json", text)
        self.assertIn("new-results.json", text)
        self.assertNotIn("fix", text.lower())

    def test_envoy_ext_proc_dependency_floors(self) -> None:
        requirements = go_module_requirements(
            (source_path('connectors/envoy/ext_proc/go.mod', root=ROOT)).read_text(encoding="utf-8")
        )
        proto_module = "github.com/envoyproxy/go-control-plane/envoy"
        version_lock = (source_path('connectors/envoy/config/envoy-ext-proc-versions.env', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertEqual(re.findall(r"(?m)^ENVOY_GO_PROTO_MODULE=(.+)$", version_lock), [proto_module])
        self.assertIn(proto_module, requirements)
        self.assertEqual(
            re.findall(r"(?m)^ENVOY_GO_PROTO_VERSION=(.+)$", version_lock),
            ["v" + ".".join(str(part) for part in requirements[proto_module])],
        )
        security_floors = {
            "google.golang.org/grpc": (1, 83, 2),
            "golang.org/x/net": (0, 58, 0),
            "golang.org/x/sys": (0, 47, 0),
            "golang.org/x/text": (0, 41, 0),
        }
        for module, floor in security_floors.items():
            with self.subTest(module=module):
                self.assertIn(module, requirements)
                self.assertGreaterEqual(requirements[module], floor)

    def test_codeql_uses_latest_trusted_base_go_version_and_bounded_cpp_scope(self) -> None:
        text = self.workflow("ci-security-codeql.yml")
        self.assertIn("ref: ${{ github.event.pull_request.base.sha || github.sha }}", text)
        self.assertEqual(
            text.count("go-version: ${{ needs.trusted-go-version.outputs.version }}"),
            2,
        )
        self.assertEqual(text.count("check-latest: false"), 3)
        self.assertNotIn("go-version-file: .go-version", text)
        self.assertIn("Set up canonical Python for the Go resolver", text)
        self.assertIn('scripts/update-go-version.py --check --json', text)
        self.assertIn('GO_REPORT="$go_report" python3 - <<\'PY\' >> "$GITHUB_OUTPUT"', text)
        self.assertIn('latest = data.get("latest_version")', text)
        self.assertIn('if version_tuple(latest) < version_tuple(current):', text)
        self.assertIn('print(f"version={latest}")', text)
        self.assertNotIn('version="$(cat -- .go-version)"', text)
        self.assertNotIn("go-version: stable", text)
        self.assertIn("connectors/envoy/ext_proc", text)
        self.assertIn("connectors/traefik/native_middleware", text)
        self.assertIn("Fuzz Traefik UDS frame parser", text)
        self.assertIn("-fuzz='^FuzzUDSFrameAndResult$'", text)
        self.assertIn("-fuzztime=15s -parallel=1", text)
        self.assertIn("make check-common-helpers-c17", text)
        self.assertIn("Fuzz Common HTTP header parser", text)
        self.assertIn("make check-common-http-header-fuzz", text)

    def test_codeql_components_match_the_central_lock_atomically(self) -> None:
        """Keep every CodeQL component on the one locked release."""

        lock_text = (source_path('ci/tooling/security-tools.lock.yml', root=ROOT)).read_text(encoding="utf-8")
        lock_entry = re.search(
            r"^  github/codeql-action:\n"
            r"    version: (?P<version>v[^\s]+)\n"
            r"    commit_sha: (?P<sha>[a-f\d]{40})\n"
            r"    upstream: https://github\.com/github/codeql-action$",
            lock_text,
            re.MULTILINE,
        )
        self.assertIsNotNone(lock_entry)
        assert lock_entry is not None
        expected = (lock_entry.group("sha"), lock_entry.group("version"))

        codeql_jobs = 0
        for job_name, job in self.jobs("ci-security-codeql.yml").items():
            init_references = re.findall(r"github/codeql-action/init@([a-f\d]{40})\s+# (v[^\s]+)", job)
            analyze_references = re.findall(r"github/codeql-action/analyze@([a-f\d]{40})\s+# (v[^\s]+)", job)
            if not init_references and not analyze_references:
                continue
            codeql_jobs += 1
            self.assertEqual(init_references, [expected], f"{job_name}: init")
            self.assertEqual(analyze_references, [expected], f"{job_name}: analyze")

        self.assertEqual(codeql_jobs, 4)
        for workflow_name in ("ci-security-osv.yml", "ci-security-scorecard.yml"):
            upload_references = re.findall(
                r"github/codeql-action/upload-sarif@([a-f\d]{40})\s+# (v[^\s]+)",
                self.workflow(workflow_name),
            )
            self.assertEqual(upload_references, [expected], workflow_name)

    def test_development_pyyaml_dependency_is_exact_safe_pin(self) -> None:
        text = (source_path('requirements-dev.txt', root=ROOT)).read_text(encoding="utf-8")
        self.assertIn("PyYAML==6.0.3", text)
        self.assertNotIn("PyYAML>=", text)

    def test_makefile_preserves_the_framework_pcre2_default_boundary(self) -> None:
        makefile = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
        self.assertIn("define export_framework_optional_provenance", makefile)
        export_list = makefile.split("FRAMEWORK_OPTIONAL_PROVENANCE_EXPORTS :=", 1)[1]
        export_list = export_list.split("$(foreach", 1)[0]
        self.assertIn("PCRE2_SHA256", export_list)
        self.assertNotIn(
            "export PCRE2_VERSION\nexport PCRE2_SOURCE_URL\nexport PCRE2_SHA256\nexport PCRE2_SHA256_URL",
            makefile,
        )
        target = (
            "print-pcre2-export:\n"
            "\t@if printenv PCRE2_SHA256 >/dev/null 2>&1; then "
            "printf 'present:<%s>' \"$$PCRE2_SHA256\"; else printf absent; fi"
        )
        environment = dict(os.environ)
        environment.pop("PCRE2_SHA256", None)
        command = ["make", "-s", f"--eval={target}", "print-pcre2-export"]
        absent = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(absent.stdout, "absent")

        empty_environment = {**environment, "PCRE2_SHA256": ""}
        environment_empty = subprocess.run(
            command,
            cwd=ROOT,
            env=empty_environment,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(environment_empty.stdout, "present:<>")

        explicit_empty = subprocess.run(
            ["make", "-s", "PCRE2_SHA256=", f"--eval={target}", "print-pcre2-export"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(explicit_empty.stdout, "present:<>")

        explicit_digest = subprocess.run(
            ["make", "-s", f"PCRE2_SHA256={PCRE2_SHA256}", f"--eval={target}", "print-pcre2-export"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(explicit_digest.stdout, f"present:<{PCRE2_SHA256}>")

    def test_security_tool_lock_has_provenance_and_digests(self) -> None:
        text = (source_path('ci/tooling/security-tools.lock.yml', root=ROOT)).read_text(encoding="utf-8")
        for tool in ("actionlint", "zizmor", "gitleaks"):
            self.assertIn(f"  {tool}:", text)
        self.assertGreaterEqual(text.count("sha256:"), 3)
        self.assertIn("full_history_gitleaks: advisory_until_historical_findings_are_triaged", text)

    def test_workflow_lint_preserves_self_repository_security_auditing(self) -> None:
        """Keep self references on the running revision and audit original files."""

        caller = self.jobs("all-connectors-no-crs.yml")["no-crs"]
        self.assertIn("uses: $/.github/workflows/reusable-five-connectors-profile.yml", caller)
        lint_jobs = self.jobs("ci-security-workflow-lint.yml")
        self.assertIn("python3 ci/tools/lint_workflows.py", lint_jobs["actionlint"])
        self.assertNotIn("--actionlint", lint_jobs["actionlint"])
        self.assertIn('"$RUNNER_TEMP/security-tools/zizmor" --offline .github/workflows', lint_jobs["zizmor"])
        self.assertNotIn("self-repository", lint_jobs["zizmor"])

    def test_nginx_ci_executes_snapshot_handoff_regressions(self) -> None:
        job = self.jobs("test-nginx.yml")["nginx-structure"]
        for module in (
            "modsecurity_connector_tests.test_nginx_exact_head_gate_contract",
            "modsecurity_connector_tests.test_nginx_exact_head_runtime_handoff",
            "modsecurity_connector_tests.test_runtime_env_snapshot_contract",
        ):
            self.assertIn(module, job)
        self.assertLess(job.index("make setup-dev"), job.index(".venv/bin/python -m unittest"))

    def test_all_workflows_default_deny_and_declare_job_permissions(self) -> None:
        for path in self.workflow_paths():
            text = path.read_text(encoding="utf-8")
            self.assertEqual(top_level_permissions(text), {}, path.name)
            for job_name, job in job_blocks(text).items():
                self.assertTrue(
                    job_has_explicit_permissions(job),
                    f"{path.name}:{job_name}",
                )

    def test_report_governance_and_strict_evidence_lifecycles_are_isolated(self) -> None:
        """Keep fresh-checkout governance separate from materialized runtime evidence."""

        text = self.workflow("verified-report-governance.yml")
        jobs = self.jobs("verified-report-governance.yml")
        self.assertEqual(set(jobs), {"report-governance"})
        job = jobs["report-governance"]
        self.assertIn("timeout-minutes: 20", job)
        self.assertIn("make report-governance", job)
        makefile = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
        lint_body = makefile.split("lint:", 1)[1].split("\nsummary:", 1)[0]
        self.assertIn("$(MAKE) report-governance", lint_body)
        self.assertNotIn("verified-report-evidence-gate", lint_body)
        strict_target = makefile.split("verified-report-evidence-gate:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("check-generated-report-layout", strict_target)
        lifecycle = (source_path('ci/runtime/lifecycle/run-verified-report-run.py', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertIn('["make", "verified-report-evidence-gate"]', lifecycle)

        # Generic CI and maintenance workflows must not invoke the strict gate;
        # only the runtime lifecycle above may do so after its producer/refresh phases.
        for path in self.workflow_paths():
            self.assertNotIn(
                "verified-report-evidence-gate",
                path.read_text(encoding="utf-8"),
                path.name,
            )
        for forbidden in (
            "verified-report-run",
            "verified-report-evidence-gate",
            "refresh-all-reports",
            "generate-system-environment-proof",
            "runtime-matrix-all",
            "upload-artifact",
            "ALLOW_RUNTIME_DOWNLOADS",
            "ALLOW_RUNTIME_BUILDS",
        ):
            self.assertNotIn(forbidden, text)

    def test_job_write_permissions_are_exactly_allowlisted(self) -> None:
        observed: dict[tuple[str, str], dict[str, str]] = {}
        for path in self.workflow_paths():
            for job_name, job in job_blocks(path.read_text(encoding="utf-8")).items():
                permissions = job_permissions(job)
                if any(value == "write" for value in permissions.values()):
                    observed[(path.name, job_name)] = permissions
                    for capability in ("checks", "issues", "packages", "id-token", "attestations"):
                        self.assertNotIn(capability, permissions, f"{path.name}:{job_name}")
        self.assertEqual(observed, EXPECTED_WRITE_PERMISSIONS)

    def test_all_checkouts_disable_persisted_credentials(self) -> None:
        for path in self.workflow_paths():
            checkout_steps = checkout_step_blocks(path.read_text(encoding="utf-8"))
            for checkout_step in checkout_steps:
                self.assertIn("persist-credentials: false", checkout_step, path.name)

    def test_lighttpd_namespace_contract_is_unprivileged_on_pull_requests(self) -> None:
        """Ordinary CI covers contracts; trusted dispatch covers kernel integration."""

        workflow = self.workflow("test-lighttpd.yml")
        jobs = self.jobs("test-lighttpd.yml")
        self.assertIn("  pull_request:\n", workflow)
        self.assertEqual(top_level_permissions(workflow), {})
        self.assertEqual(set(jobs), {"lighttpd-contract"})
        job = jobs["lighttpd-contract"]
        self.assertIn(
            "ref: ${{ github.event.pull_request.head.sha || github.sha }}", job
        )
        self.assertIn("persist-credentials: false", job)
        self.assertIn(
            "Run private fixture namespace contract tests", job
        )
        self.assertNotIn("LIGHTTPD_REQUIRE_NAMESPACE_INTEGRATION", job)
        self.assertIn('PYTHONDONTWRITEBYTECODE: "1"', job)
        self.assertIn("set -euo pipefail", job)
        self.assertIn(
            'namespace_temp_root="$(/usr/bin/mktemp -d "${RUNNER_TEMP}/lighttpd-namespace-contract.XXXXXX")"',
            job,
        )
        self.assertIn('/usr/bin/chmod 700 -- "$namespace_temp_root"', job)
        self.assertIn(
            'export LIGHTTPD_NAMESPACE_TEST_TEMP_PARENT="$namespace_temp_root"',
            job,
        )
        self.assertIn(
            "python3 -m unittest -v connector_suite.adapters.lighttpd.tests.test_no_crs_fixture_namespace",
            job,
        )
        for forbidden in ("continue-on-error:", "|| true", "exit 0", "sudo", "unshare "):
            self.assertNotIn(forbidden, job)

    def test_with_crs_no_mrts_workflow_is_five_real_fail_closed_runtime_jobs(self) -> None:
        """Keep the narrow CRS workflow on real no-MRTS runtime paths only."""

        workflow = self.workflow("test-connectors-with-crs-no-mrts.yml")
        jobs = self.jobs("test-connectors-with-crs-no-mrts.yml")
        self.assertEqual(set(jobs), {"connector-mode", "aggregate-with-crs-no-mrts"})
        job = jobs["connector-mode"]

        self.assertIn("  pull_request:\n    branches: [master]\n", workflow)
        self.assertIn("  workflow_dispatch:\n", workflow)
        self.assertIn(
            "    inputs:\n"
            "      parent_sha:\n"
            "        description: Exact full candidate head SHA for this manual profile run\n"
            "        required: true\n"
            "        type: string\n"
            "      base_sha:\n"
            "        description: Exact full checked base SHA for this manual profile run\n"
            "        required: true\n"
            "        type: string\n",
            workflow,
        )
        for forbidden in (
            "pull_request_target:",
            "workflow_run:",
            "workflow_call:",
            "repository_dispatch:",
            "\n  push:",
            "secrets.",
            "github.token",
            "GITHUB_TOKEN",
            "GH_TOKEN",
        ):
            self.assertNotIn(forbidden, workflow)
        self.assertEqual(top_level_permissions(workflow), {})
        self.assertEqual(job_permissions(job), {"contents": "read"})
        self.assertIsNone(job_if_expression(job))
        self.assertNotIn("|| github.sha", workflow)

        expected_rows = [
            ("apache", "with-crs", "no-mrts", "apache"),
            ("envoy", "with-crs", "no-mrts", "shared"),
            ("haproxy", "with-crs", "no-mrts", "haproxy"),
            ("lighttpd", "with-crs", "no-mrts", "shared"),
            ("traefik", "with-crs", "no-mrts", "shared"),
        ]
        matrix_rows = re.findall(
            r"^          - connector: ([a-z]+)\n"
            r"^            crs: ([a-z-]+)\n"
            r"^            mrts: ([a-z-]+)\n"
            r"^            runtime_component_target: ([a-z]+)$",
            job,
            re.MULTILINE,
        )
        self.assertEqual(matrix_rows, expected_rows)
        self.assertIn(
            "RUNTIME_COMPONENT_TARGET: ${{ matrix.runtime_component_target }}",
            job,
        )
        self.assertNotIn("coverage_kind", job)
        self.assertNotIn("verified-full-matrix-job", job)
        self.assertNotIn("run-full-matrix-job.py", job)

        checkout_steps = checkout_step_blocks(job)
        self.assertEqual(len(checkout_steps), 1)
        checkout = checkout_steps[0]
        self.assertIn(
            locked_action_pin("actions/checkout"),
            checkout,
        )
        self.assertIn(
            "ref: ${{ github.event.pull_request.head.sha || inputs.parent_sha }}",
            checkout,
        )
        self.assertIn("submodules: recursive", checkout)
        self.assertIn("persist-credentials: false", checkout)
        self.assertIn(
            locked_action_reference_with_version("actions/setup-python"),
            job,
        )
        self.assertIn(
            locked_action_reference_with_version("actions/upload-artifact"),
            job,
        )

        self.assertIn(
            "EXPECTED_PARENT_SHA: ${{ github.event.pull_request.head.sha || inputs.parent_sha }}",
            job,
        )
        self.assertIn(
            "EXPECTED_BASE_SHA: ${{ github.event.pull_request.base.sha || inputs.base_sha }}",
            job,
        )
        literal_framework_shas = re.findall(
            r"^\s+(?:EXPECTED_)?(?:FRAMEWORK|MRTS)_SHA: ([0-9a-f]{40})$", workflow, re.MULTILINE
        )
        self.assertEqual(literal_framework_shas, [])
        self.assertEqual(workflow.count("FRAMEWORK_SHA: ${{ steps.verify-revisions.outputs.framework_sha }}"), 3)
        self.assertEqual(workflow.count("MRTS_SHA: ${{ steps.verify-revisions.outputs.mrts_sha }}"), 3)
        verification = job.split("      - name: Verify pinned Parent, Framework, and MRTS revisions\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("id: verify-revisions", verification)
        self.assertIn("python3 -I ci/tools/read-framework-revisions.py", verification)
        self.assertIn('--parent-sha "$EXPECTED_PARENT_SHA" --format github-output >> "$GITHUB_OUTPUT"', verification)
        self.assertIn('test "$parent_commit" = "$EXPECTED_PARENT_SHA"', job)
        self.assertIn('test "$EXPECTED_PARENT_SHA" != "$EXPECTED_BASE_SHA"', job)
        self.assertIn("python3 ci/tools/install-ci-dependencies.py --ci-toolcache", job)
        self.assertIn("--framework-lock modules/ModSecurity-test-Framework/requirements-ci.lock", job)
        self.assertIn('test "${#CRS_RUNTIME_RUN_ID}" -le 48', job)
        self.assertIn("EVIDENCE_ROOT: \"\"", job)

        self.assertIn("- name: Prepare fresh CRS source for Apache and HAProxy", job)
        self.assertIn(". ci/runtime/lifecycle/prepare-fresh-crs-source.sh", job)
        self.assertIn('sh "$FRAMEWORK_ROOT/ci/provisioning/fetch-crs.sh"', job)
        self.assertIn(
            'printf \'%s\\n\' "SOURCE_ROOT=$SOURCE_ROOT" "CRS_SOURCE_DIR=$CRS_SOURCE_DIR" >> "$GITHUB_ENV"',
            job,
        )
        preparation = job.split(
            "      - name: Prepare fresh CRS source for Apache and HAProxy\n", 1
        )[1].split("      - name: Prepare HAProxy runtime evidence boundary\n", 1)[0]
        self.assertIn('case "$CONNECTOR" in', preparation)
        self.assertIn("apache|haproxy)", preparation)
        self.assertIn(
            'printf \'%s\\n\' "SOURCE_ROOT=$SOURCE_ROOT" "CRS_SOURCE_DIR=$CRS_SOURCE_DIR" >> "$GITHUB_ENV"',
            preparation,
        )
        runtime = job.split(
            "      - name: Run selected real with-CRS no-MRTS runtime\n", 1
        )[1].split("      - name: Project HAProxy runtime evidence\n", 1)[0]
        runtime_script = runtime.split("        run: |\n", 1)[1]
        self.assertIn(
            "SETUP_PYTHON_PATH: $" + "{{ steps.setup-python.outputs.python-path }}",
            runtime,
        )
        self.assertIn('PYTHON="$SETUP_PYTHON_PATH"', runtime_script)
        for runtime_value in (
            "RUNTIME_UID",
            "RUNTIME_GID",
            "RUNTIME_PARENT_SHA",
            "RUNTIME_FRAMEWORK_SHA",
            "RUNTIME_MRTS_SHA",
        ):
            self.assertIn(
                f"{runtime_value}: $" + "{{ steps.prepare-haproxy-runtime-evidence.outputs.",
                runtime,
            )
            self.assertIn(f'"${runtime_value}"', runtime_script)
        self.assertNotIn(
            "$" + "{{ steps.prepare-haproxy-runtime-evidence.outputs.",
            runtime_script,
        )
        self.assertNotIn("prepare-fresh-crs-source.sh", runtime)
        self.assertNotIn('fetch-crs.sh', runtime)
        self.assertEqual(
            job.count('. "$FRAMEWORK_ROOT/ci/lib/common.sh"'),
            2,
        )
        self.assertLess(
            job.index("prepare-fresh-crs-source.sh"),
            job.index("make verified-apache-case CASE=crs_sqli_anomaly_block"),
        )
        self.assertLess(
            job.index("prepare-fresh-crs-source.sh"),
            job.index('/usr/bin/make -C "$GITHUB_WORKSPACE" verified-haproxy-case CASE=crs_sqli_anomaly_block'),
        )
        self.assertIn(
            'make verified-apache-case CASE=crs_sqli_anomaly_block CRS="$CRS" MRTS="$MRTS"',
            job,
        )
        self.assertIn(
            '/usr/bin/make -C "$GITHUB_WORKSPACE" verified-haproxy-case CASE=crs_sqli_anomaly_block CRS=with-crs MRTS=no-mrts',
            job,
        )
        self.assertEqual(
            job.count('make with-crs-no-mrts-runtime CONNECTOR="$CONNECTOR"'),
            1,
        )
        self.assertIn("envoy|lighttpd|traefik)", job)
        self.assertIn("lighttpd:with-crs:no-mrts", job)
        self.assertNotIn("runtime-with-crs-no-mrts-connector", job)
        self.assertNotIn("action_deny_phase1", job)
        self.assertNotIn("2101", job)

        # The trusted Lighttpd namespace launcher remains inside the Parent
        # runtime target.  The workflow neither skips this cell nor supplies a
        # host-side fallback if that launcher rejects the runner environment.
        for forbidden in (
            "continue-on-error:",
            "|| true",
            "exit 0",
            "run_no_crs_fixture_trusted_namespace.py",
        ):
            self.assertNotIn(forbidden, job)
        self.assertIn("if-no-files-found: error", job)
        self.assertNotIn("if-no-files-found: ignore", job)
        self.assertIn("retention-days: 10", job)
        for step_id in (
            "checkout",
            "setup-python",
            "verify-python",
            "verify-revisions",
            "install-framework-ci",
            "verify-runtime-cell",
            "initialize-runtime-roots",
            "prepare-crs-source",
            "prepare-haproxy-runtime-evidence",
            "runtime",
            "project-haproxy-runtime-evidence",
            "verify-haproxy-runtime-evidence",
            "produce-profile-cell",
            "validate-apache-runtime-evidence",
            "prepare-non-haproxy-runtime-evidence",
            "upload-apache-runtime-evidence",
            "upload-apache-runtime-failure-receipt",
            "upload-non-haproxy-runtime-evidence",
            "upload-non-haproxy-runtime-failure-receipt",
            "upload-runtime-evidence",
        ):
            self.assertIn(f"id: {step_id}", job)
        self.assertEqual(
            job.count(locked_action_reference_with_version("actions/upload-artifact")),
            5,
        )
        producer = job.split("      - name: Produce canonical with-CRS no-MRTS profile cell\n", 1)[1].split(
            "      - name: Upload Apache runtime evidence\n", 1
        )[0]
        self.assertIn('export CONNECTOR_ROOT="$GITHUB_WORKSPACE" REPO_ROOT="$GITHUB_WORKSPACE"', producer)
        self.assertIn('. "$FRAMEWORK_ROOT/ci/lib/common.sh"', producer)
        self.assertIn('crs_commit="$CRS_APPROVED_COMMIT"', producer)
        self.assertIn('crs_rule_sha256="$CRS_RULE_FILE_SHA256"', producer)
        self.assertNotIn("sed -n 's/^CRS_", producer)
        self.assertIn("--crs-source-root \"$crs_source_root\"", producer)
        self.assertIn("apache)\n              source_root=", producer)
        self.assertIn("haproxy_source_args=(", producer)
        self.assertIn("--haproxy-evidence-sha256 \"$HAPROXY_EVIDENCE_SHA256\"", producer)
        self.assertIn("--haproxy-manifest-sha256 \"$HAPROXY_MANIFEST_SHA256\"", producer)
        self.assertIn(
            'crs_source_root="$VERIFIED_ROOT/runs/$CONNECTOR/$CELL_RUN_ID_VALUE/crs-fresh-source/coreruleset"',
            producer,
        )
        self.assertIn("HAPROXY_EVIDENCE_SHA256: ${{ steps.verify-haproxy-runtime-evidence.outputs.evidence_sha256 }}", producer)
        self.assertIn("HAPROXY_MANIFEST_SHA256: ${{ steps.verify-haproxy-runtime-evidence.outputs.manifest_sha256 }}", producer)
        boundary = job.split("      - name: Prepare HAProxy runtime evidence boundary\n", 1)[1].split(
            "      - name: Run selected real with-CRS no-MRTS runtime\n", 1
        )[0]
        self.assertIn("if: matrix.connector == 'haproxy'", boundary)
        self.assertIn(
            'rev-parse "$PARENT_SHA:ci/runtime/lifecycle/project-haproxy-runtime-evidence.py"',
            boundary,
        )
        self.assertIn("projector_blob", boundary)
        self.assertIn("TRUSTED_EVIDENCE_STAGE_ROOT: /tmp", boundary)
        self.assertIn(
            'stage_parent=$(/usr/bin/sudo -n /usr/bin/mktemp -d -- "$TRUSTED_EVIDENCE_STAGE_ROOT/haproxy-runtime-evidence-parent.XXXXXXXX")',
            boundary,
        )
        self.assertIn('projector_source="$stage_parent/verified-projector.py"', boundary)
        self.assertIn('/usr/bin/sudo -n /usr/bin/chmod 0444 -- "$projector_source"', boundary)
        self.assertIn("runner_temp_identity=", boundary)
        self.assertIn("probe_uid=$(", boundary)
        for required in (
            "/usr/bin/unshare",
            "--mount",
            "--pid",
            "--fork",
            "--kill-child=SIGKILL",
            "--mount-proc=/proc",
            "--propagation private",
            "/usr/bin/setpriv",
            "--no-new-privs",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            'test "$probe_uid" = "$runtime_uid"',
        ):
            self.assertIn(required, boundary)
        for forbidden in (
            "seal-helper",
            "SEALED_HELPER",
            "sudo -n /usr/bin/python3",
            "sudo -n sh",
            "find ",
            "cp -",
        ):
            self.assertNotIn(forbidden, boundary)
        self.assertIn("HAPROXY_EVIDENCE_RECEIPT=1", runtime)
        self.assertIn("HAPROXY_EVIDENCE_RECEIPT_PROJECTOR=", runtime)
        self.assertIn("EXPECTED_PARENT_SHA=", runtime)
        self.assertIn("EXPECTED_FRAMEWORK_SHA=", runtime)
        self.assertIn("EXPECTED_MRTS_SHA=", runtime)
        self.assertIn("/usr/bin/unshare", runtime)
        self.assertIn("/usr/bin/setpriv", runtime)
        self.assertLess(runtime.index("/usr/bin/setpriv"), runtime.index("/usr/bin/make"))
        runtime_root_launch, dropped_runtime = runtime.split("-- /usr/bin/env -i", 1)
        self.assertNotIn("$GITHUB_WORKSPACE", runtime_root_launch)
        for forbidden in (
            "GITHUB_ENV",
            "GITHUB_OUTPUT",
            "GITHUB_PATH",
            "GITHUB_STATE",
            "HAPROXY_EVIDENCE_RECEIPT_HELPER",
            "seal-helper",
            "sudo -n /usr/bin/python3",
        ):
            self.assertNotIn(forbidden, dropped_runtime)
        project = job.split("      - name: Project HAProxy runtime evidence\n", 1)[1].split(
            "      - name: Verify HAProxy runtime evidence\n", 1
        )[0]
        self.assertIn("if: matrix.connector == 'haproxy' && steps.runtime.outcome == 'success'", project)
        self.assertIn("TRUSTED_SOURCE_ROOT", project)
        self.assertIn("TRUSTED_RUNNER_TEMP", project)
        self.assertIn("RUNTIME_GID", project)
        self.assertIn("PROJECTOR_BLOB", project)
        self.assertIn("PROJECTOR_SOURCE", project)
        self.assertIn("STAGE_PARENT", project)
        self.assertIn("TRUSTED_EVIDENCE_STAGE_ROOT", project)
        self.assertIn("run_runner_projector()", project)
        self.assertIn("run_evidence_projector()", project)
        self.assertIn("hashlib.sha1", project)
        self.assertIn("exec(compile(source", project)
        self.assertIn('stage_root="$STAGE_PARENT/package"', project)
        self.assertIn("sudo -n /usr/bin/chown --no-dereference", project)
        self.assertIn(
            'sudo -n /usr/bin/chown --no-dereference "$EVIDENCE_UID:$RUNTIME_GID" -- "$stage_root"',
            project,
        )
        self.assertIn('= "$EVIDENCE_UID:$RUNTIME_GID:700"', project)
        self.assertIn("run_runner_projector export-source-receipt", project)
        self.assertIn("| /usr/bin/head --bytes=16385", project)
        self.assertIn("| run_evidence_projector project-document --source-document-stdin", project)
        self.assertNotIn("source_document=", project)
        self.assertNotIn("--source-document ", project)
        self.assertLess(
            project.index("run_runner_projector export-source-receipt"),
            project.index("| /usr/bin/head --bytes=16385"),
        )
        self.assertLess(
            project.index("| /usr/bin/head --bytes=16385"),
            project.index("| run_evidence_projector project-document --source-document-stdin"),
        )
        self.assertIn('--upload-gid "$RUNTIME_GID"', project)
        for forbidden in (
            "seal-helper",
            "SEALED_HELPER",
            "sudo -n /usr/bin/python3",
            "find ",
            "cp -",
            "|| true",
        ):
            self.assertNotIn(forbidden, project)
        verification = job.split("      - name: Verify HAProxy runtime evidence\n", 1)[1].split(
            "      - name: Upload non-HAProxy runtime evidence\n", 1
        )[0]
        self.assertIn(
            "if: matrix.connector == 'haproxy' && steps.project-haproxy-runtime-evidence.outcome == 'success'",
            verification,
        )
        self.assertIn("RUNTIME_GID", verification)
        self.assertIn("EVIDENCE_UID", verification)
        self.assertIn("EVIDENCE_GID", verification)
        self.assertIn("PROJECTOR_SOURCE", verification)
        self.assertIn("TRUSTED_EVIDENCE_STAGE_ROOT", verification)
        self.assertIn("hashlib.sha1", verification)
        self.assertIn("run_evidence_projector verify", verification)
        self.assertIn('--upload-gid "$RUNTIME_GID"', verification)
        self.assertNotIn("safe.directory=", project)
        self.assertNotIn("safe.directory=", verification)
        self.assertNotIn("sudo -n /usr/bin/python3", verification)
        self.assertNotIn("seal-helper", verification)
        for projector_block in (project, verification):
            self.assertIn("sudo -n /usr/bin/env -i", projector_block)
            self.assertIn("/usr/bin/unshare", projector_block)
            self.assertIn("/usr/bin/setpriv", projector_block)
            self.assertIn("--no-new-privs", projector_block)
            self.assertIn("--inh-caps=-all", projector_block)
            self.assertIn("--ambient-caps=-all", projector_block)
            self.assertIn("--bounding-set=-all", projector_block)
            self.assertIn('--reuid="$EVIDENCE_UID"', projector_block)
            self.assertIn('--regid="$EVIDENCE_GID"', projector_block)
            self.assertNotIn("sudo -n -u nobody -g nogroup", projector_block)
        self.assertIn('--reuid="$RUNTIME_UID"', project)
        self.assertIn('--regid="$RUNTIME_GID"', project)
        projector_root_launcher, constrained_projector = project.split("-- /usr/bin/env -i", 1)
        self.assertNotIn("$GITHUB_WORKSPACE", projector_root_launcher)
        self.assertLess(
            constrained_projector.index("/usr/bin/python3 -I -c"),
            constrained_projector.index("exec(compile(source"),
        )
        non_haproxy_upload = job.split("      - name: Upload non-HAProxy runtime evidence\n", 1)[1].split(
            "      - name: Upload non-HAProxy runtime failure receipt\n", 1
        )[0]
        self.assertIn(
            "if: always() && matrix.connector != 'haproxy' && matrix.connector != 'apache' && steps.runtime.outcome == 'success' && steps.prepare-non-haproxy-runtime-evidence.outcome == 'success' && steps.produce-profile-cell.outcome == 'success'",
            non_haproxy_upload,
        )
        self.assertNotIn("verified-haproxy-case", non_haproxy_upload)
        self.assertNotIn("verified-apache-case", non_haproxy_upload)
        self.assertIn("${{ env.VERIFIED_RUN_ROOT }}/profile-cell", non_haproxy_upload)
        self.assertNotIn("${{ env.VERIFIED_RUN_ROOT }}/failure-receipt.json", non_haproxy_upload)
        non_haproxy_failure_upload = job.split(
            "      - name: Upload non-HAProxy runtime failure receipt\n", 1
        )[1].split("      - name: Upload real runtime evidence\n", 1)[0]
        self.assertIn("steps.runtime.outcome != 'success'", non_haproxy_failure_upload)
        self.assertIn("${{ env.VERIFIED_RUN_ROOT }}/failure-receipt.json", non_haproxy_failure_upload)
        self.assertNotIn("${{ env.VERIFIED_RUN_ROOT }}/evidence", non_haproxy_failure_upload)
        apache_upload = job.split("      - name: Upload Apache runtime evidence\n", 1)[1].split(
            "      - name: Upload Apache runtime failure receipt\n", 1
        )[0]
        self.assertIn("matrix.connector == 'apache'", apache_upload)
        self.assertIn("steps.runtime.outcome == 'success'", apache_upload)
        self.assertIn("steps.produce-profile-cell.outcome == 'success'", apache_upload)
        self.assertIn("${{ env.VERIFIED_RUN_ROOT }}/profile-cell", apache_upload)
        self.assertIn("if-no-files-found: error", apache_upload)
        apache_failure_upload = job.split(
            "      - name: Upload Apache runtime failure receipt\n", 1
        )[1].split("      - name: Validate generic runtime evidence or retain failure receipt\n", 1)[0]
        self.assertIn("steps.runtime.outcome != 'success'", apache_failure_upload)
        self.assertIn("${{ env.VERIFIED_RUN_ROOT }}/failure-receipt.json", apache_failure_upload)
        self.assertNotIn("verified-apache-case", apache_failure_upload)
        upload = job.split("      - name: Upload real runtime evidence\n", 1)[1].split(
            "      - name: Write connector runtime overview\n", 1
        )[0]
        self.assertIn(
            "if: matrix.connector == 'haproxy' && steps.verify-haproxy-runtime-evidence.outcome == 'success' && steps.produce-profile-cell.outcome == 'success'",
            upload,
        )
        self.assertIn("${{ env.VERIFIED_RUN_ROOT }}/profile-cell", upload)
        self.assertNotIn("BUILD_ROOT", upload)
        self.assertNotIn("EVIDENCE_ROOT", upload)
        self.assertIn("Cleanup HAProxy runtime evidence stage", upload)
        self.assertIn("if: always() && matrix.connector == 'haproxy'", upload)
        self.assertIn('/usr/bin/sudo -n /usr/bin/rm -rf -- "$STAGE_PARENT"', upload)
        self.assertLess(
            job.index('/usr/bin/make -C "$GITHUB_WORKSPACE" verified-haproxy-case CASE=crs_sqli_anomaly_block'),
            job.index("      - name: Project HAProxy runtime evidence\n"),
        )
        summary = job.split("      - name: Write connector runtime overview\n", 1)[1]
        self.assertIn("if: always()", summary)
        self.assertIn(
            "PARENT_SHA: $" + "{{ github.event.pull_request.head.sha || inputs.parent_sha }}",
            summary,
        )
        self.assertIn(
            'rev-parse "$PARENT_SHA:ci/runtime/lifecycle/summarize-with-crs-no-mrts-workflow.py"',
            summary,
        )
        self.assertIn("summary_blob=", summary)
        self.assertIn("cat-file -e \"${summary_blob}^{blob}\"", summary)
        self.assertIn("sudo -n /usr/bin/env -i", summary)
        self.assertIn("/usr/bin/unshare", summary)
        self.assertIn("/usr/bin/setpriv", summary)
        self.assertIn("--no-new-privs", summary)
        self.assertIn("exec(compile(source", summary)
        self.assertNotIn(
            'python3 ci/runtime/lifecycle/summarize-with-crs-no-mrts-workflow.py',
            summary,
        )
        summary_root_launcher = summary.split("sudo -n /usr/bin/env -i", 1)[1].split(
            "-- /usr/bin/env -i", 1
        )[0]
        self.assertNotIn("$GITHUB_WORKSPACE", summary_root_launcher)
        self.assertLess(summary.index("/usr/bin/setpriv"), summary.index("exec(compile(source"))
        self.assertNotIn("--summary-file", summary)
        for environment_name, step_id in (
            ("CHECKOUT_OUTCOME", "checkout"),
            ("SETUP_PYTHON_OUTCOME", "setup-python"),
            ("VERIFY_PYTHON_OUTCOME", "verify-python"),
            ("VERIFY_REVISIONS_OUTCOME", "verify-revisions"),
            ("INSTALL_DEPENDENCIES_OUTCOME", "install-framework-ci"),
            ("VERIFY_CELL_OUTCOME", "verify-runtime-cell"),
            ("INITIALIZE_ROOTS_OUTCOME", "initialize-runtime-roots"),
            ("PREPARE_CRS_OUTCOME", "prepare-crs-source"),
            ("RUNTIME_OUTCOME", "runtime"),
        ):
            self.assertIn(f"{environment_name}: ${{{{ steps.{step_id}.outcome }}}}", summary)
        self.assertIn("UPLOAD_EVIDENCE_OUTCOME: ${{ matrix.connector == 'haproxy'", summary)
        self.assertIn("steps.upload-apache-runtime-failure-receipt.outcome", summary)
        self.assertIn("steps.upload-non-haproxy-runtime-failure-receipt.outcome", summary)
        self.assertLess(
            job.index("      - name: Prepare HAProxy runtime evidence boundary\n"),
            job.index("      - name: Run selected real with-CRS no-MRTS runtime\n"),
        )
        self.assertLess(
            job.index("      - name: Project HAProxy runtime evidence\n"),
            job.index("      - name: Verify HAProxy runtime evidence\n"),
        )
        self.assertLess(
            job.index("      - name: Upload real runtime evidence\n"),
            job.index("      - name: Write connector runtime overview\n"),
        )
        runtime_runner = (source_path('ci/runtime/lifecycle/run-with-crs-no-mrts.sh', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "TASK_ROOT=${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-crs-runtime}",
            runtime_runner,
        )
        self.assertIn("EXPECTED_EVIDENCE_ROOT=$TASK_ROOT/evidence", runtime_runner)
        # The explicit workflow root selects the first branch of the shell's
        # ``:-`` expansion above, so the runner-owned evidence is rooted
        # directly below it rather than below the fallback suffix.
        self.assertIn(
            "${{ env.VERIFIED_RUN_ROOT }}/profile-cell",
            job,
        )
        self.assertIn(
            "${{ env.VERIFIED_RUN_ROOT }}/failure-receipt.json",
            job,
        )
        self.assertNotIn(
            "${{ env.BUILD_ROOT }}/verified-apache-case/with-crs/no-mrts/results",
            non_haproxy_upload,
        )
        helper = (source_path('ci/runtime/lifecycle/prepare-with-crs-no-mrts-upload.py', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertIn("parent_runtime_attestation", helper)
        self.assertIn("connector_commit", helper)
        self.assertIn("failure receipt", helper)
        validation = job.split(
            "      - name: Validate generic runtime evidence or retain failure receipt\n", 1
        )[1].split("      - name: Write connector runtime overview\n", 1)[0]
        self.assertIn(
            "if: always() && matrix.connector != 'haproxy' && matrix.connector != 'apache'",
            validation,
        )
        self.assertIn("steps.runtime.outcome", validation)
        self.assertIn("prepare-with-crs-no-mrts-upload.py", validation)

        aggregate = jobs["aggregate-with-crs-no-mrts"]
        self.assertIn("needs: connector-mode", aggregate)
        self.assertIn("if: always()", aggregate)
        self.assertIn("fetch-depth: 0", aggregate)
        self.assertIn(
            "ref: ${{ github.event.pull_request.head.sha || inputs.parent_sha }}",
            aggregate,
        )
        self.assertIn(
            "EXPECTED_BASE_SHA: ${{ github.event.pull_request.base.sha || inputs.base_sha }}",
            aggregate,
        )
        self.assertIn(
            locked_action_reference_with_version("actions/download-artifact"),
            aggregate,
        )
        self.assertIn("pattern: with-crs-no-mrts-*-${{ github.run_id }}-${{ github.run_attempt }}", aggregate)
        self.assertIn("merge-multiple: false", aggregate)
        self.assertNotIn('find "$CELL_ROOT"', aggregate)
        aggregate_step = aggregate.split("      - name: Aggregate exact five canonical profile cells\n", 1)[1].split(
            "      - name: Upload canonical five-connector aggregate\n", 1
        )[0]
        self.assertIn('export CONNECTOR_ROOT="$PWD" REPO_ROOT="$PWD"', aggregate_step)
        self.assertIn('FRAMEWORK_ROOT="$PWD/modules/ModSecurity-test-Framework"', aggregate_step)
        self.assertIn('test "${#FRAMEWORK_SHA}" -eq 40', aggregate_step)
        self.assertIn('framework_commit=$(git -C "$FRAMEWORK_ROOT" rev-parse HEAD)', aggregate_step)
        self.assertIn('test "$framework_commit" = "$FRAMEWORK_SHA"', aggregate_step)
        self.assertIn('. "$FRAMEWORK_ROOT/ci/lib/common.sh"', aggregate_step)
        self.assertLess(
            aggregate_step.index('test "$framework_commit" = "$FRAMEWORK_SHA"'),
            aggregate_step.index('. "$FRAMEWORK_ROOT/ci/lib/common.sh"'),
        )
        self.assertIn('crs_commit="$CRS_APPROVED_COMMIT"', aggregate_step)
        self.assertIn('crs_rule_sha256="$CRS_RULE_FILE_SHA256"', aggregate_step)
        self.assertNotIn("sed -n 's/^CRS_", aggregate_step)
        self.assertIn("aggregate-five-connector-with-crs-no-mrts.py", aggregate)
        self.assertIn("--artifact-root \"$CELL_ROOT\"", aggregate)
        self.assertIn("--output-dir \"$CELL_ROOT/aggregate\"", aggregate)
        self.assertIn("with-crs-no-mrts-aggregate-${{ github.run_id }}-${{ github.run_attempt }}", aggregate)

    def test_pr_apr_util_provenance_job_is_unconditional_and_read_only(self) -> None:
        workflow = self.workflow("ci-security-workflow-lint.yml")
        jobs = self.jobs("ci-security-workflow-lint.yml")
        job = jobs["apr-util-provenance"]

        self.assertIn("  pull_request:\n", workflow)
        self.assertNotIn("    branches:", workflow.partition("  pull_request:\n")[2].partition("  push:")[0])
        self.assertNotIn("if:", job)
        self.assertEqual(job_permissions(job), {"contents": "read"})
        self.assertNotIn("secrets.", job)
        self.assertNotIn("github.token", job)
        checkout_steps = checkout_step_blocks(job)
        self.assertEqual(len(checkout_steps), 1)
        self.assertIn(locked_action_pin("actions/checkout"), checkout_steps[0])
        self.assertIn("submodules: recursive", checkout_steps[0])
        self.assertIn("persist-credentials: false", checkout_steps[0])
        self.assertIn(
            "python3 -m unittest -v modsecurity_connector_tests.test_framework_apr_util_provenance modsecurity_connector_tests.test_apr_util_static_contract",
            job,
        )
        self.assertIn(locked_action_pin("actions/setup-python"), job)
        self.assertIn("id: setup-python", job)
        self.assertIn("python-version-file: .python-version", job)
        self.assertIn("check-latest: false", job)
        self.assertIn(
            'python3 ci/checks/common/check-python-interpreter-contract.py --version-file .python-version --expected-python "$EXPECTED_PYTHON"',
            job,
        )
        self.assertNotIn("pip ", job)
        self.assertNotIn("curl ", job)
        self.assertNotIn("wget ", job)

    def test_trusted_nginx_root_broker_has_no_pr_code_at_root_boundary(self) -> None:
        text = self.workflow("nginx-root-broker.yml")
        self.assertIn("workflow_call:", text)
        self.assertNotIn("pull_request:", text)
        self.assertNotIn("pull_request_target:", text)
        self.assertIn("ACTUAL_CALLER_WORKFLOW_REF: ${{ github.workflow_ref }}", text)
        self.assertIn(
            "EXPECTED_CALLER_WORKFLOW_REF: Easton97-Jens/ModSecurity-conector/.github/workflows/run-protected-nginx-root-broker.yml@refs/heads/master",
            text,
        )
        self.assertNotIn("EXPECTED_WORKFLOW_REF:", text)
        self.assertIn("CALLER_SHA: ${{ github.sha }}", text)
        self.assertIn("CALLER_WORKFLOW_SHA: ${{ github.workflow_sha }}", text)
        self.assertIn('git cat-file -e "$CALLER_SHA^{commit}"', text)
        self.assertIn('git merge-base --is-ancestor "$CALLER_SHA" FETCH_HEAD', text)
        self.assertIn("validate-caller-workflow", text)
        self.assertIn('git merge-base --is-ancestor "$BROKER_SHA" FETCH_HEAD', text)
        self.assertIn('git ls-tree "$BROKER_SHA" -- modules/ModSecurity-test-Framework', text)
        self.assertIn("verify_broker_source .github/workflows/nginx-root-broker.yml", text)
        self.assertIn('git rev-parse "$BROKER_SHA:$source_path"', text)
        self.assertIn('git hash-object "$source_path"', text)
        self.assertIn("verify_broker_source ci/runtime/broker/nginx_root_broker.py", text)
        self.assertIn("prepare-fresh-crs-source.sh", text)
        self.assertIn("prepare-crs-bundle", text)
        self.assertEqual(
            text.count(
                "          RUNTIME_COMPONENT_SNAPSHOT_CONTRACT: protected-nginx-broker"
            ),
            1,
        )
        self.assertLess(
            text.index("RUNTIME_COMPONENT_SNAPSHOT_CONTRACT: protected-nginx-broker"),
            text.index("make fetch-deps"),
        )
        self.assertLess(
            text.index("make fetch-deps"),
            text.index("prepare-from-snapshot"),
        )
        self.assertNotIn(
            "RUNTIME_COMPONENT_SNAPSHOT_CONTRACT: ${{", text
        )
        self.assertIn("verify-runtime-profile", text)
        self.assertIn("cleanup.json", text)
        self.assertIn("sudo -- /usr/bin/python3 -I ci/runtime/broker/nginx_root_broker.py action", text)
        self.assertNotIn("uses: ./", text)
        for forbidden in (
            "sudo -E",
            "sudo sh -c",
            "sudo bash -c",
            "shell: bash -c",
            "id-token: write",
            "--broker-parent",
            "--staging-root",
            "--runtime-snapshot",
            "sudo python",
        ):
            self.assertNotIn(forbidden, text)

    def test_protected_master_caller_is_exactly_pinned_and_fail_closed(self) -> None:
        text = self.workflow(PROTECTED_NGINX_BROKER_CALLER_WORKFLOW)
        self.assertEqual(protected_nginx_broker_caller_errors(text), [])
        mutations = {
            "broker master ref": (
                PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE,
                PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE.replace(
                    f"@{PROTECTED_NGINX_BROKER_SHA}", "@master"
                ),
            ),
            "broker branch ref": (
                PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE,
                PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE.replace(
                    f"@{PROTECTED_NGINX_BROKER_SHA}", "@fix/unsafe"
                ),
            ),
            "local reusable workflow": (
                PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE,
                "./.github/workflows/nginx-root-broker.yml",
            ),
            "wrong broker SHA": (
                PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE,
                PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE.replace(
                    PROTECTED_NGINX_BROKER_SHA,
                    "0" * 40,
                ),
            ),
            "duplicate broker reference": (
                f"    uses: {PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE}",
                "\n".join(
                    (
                        f"    uses: {PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE}",
                        f"    uses: {PROTECTED_NGINX_BROKER_REUSABLE_REFERENCE}",
                    )
                ),
            ),
            "mutable Framework SHA": (
                f"framework_sha: {PROTECTED_NGINX_BROKER_FRAMEWORK_SHA}",
                "framework_sha: " + "0" * 40,
            ),
            "duplicate broker input": (
                f"      framework_sha: {PROTECTED_NGINX_BROKER_FRAMEWORK_SHA}",
                "\n".join(
                    (
                        f"      framework_sha: {PROTECTED_NGINX_BROKER_FRAMEWORK_SHA}",
                        f"      framework_sha: {PROTECTED_NGINX_BROKER_FRAMEWORK_SHA}",
                    )
                ),
            ),
            "missing master guard": (
                "github.ref == 'refs/heads/master' &&\n",
                "",
            ),
            "wrong repository guard": (
                "github.repository == 'Easton97-Jens/ModSecurity-conector'",
                "github.repository == 'attacker/example'",
            ),
            "missing fork guard": (
                "github.event.repository.fork == false &&\n",
                "",
            ),
            "missing default branch guard": (
                "github.event.repository.default_branch == 'master'",
                "github.event.repository.default_branch == 'main'",
            ),
            "short-circuited master guard": (
                "github.event_name == 'workflow_dispatch'",
                "true || github.event_name == 'workflow_dispatch'",
            ),
            "pull request trigger": (
                "  workflow_dispatch:\n",
                "  pull_request:\n  workflow_dispatch:\n",
            ),
            "pull request target trigger": (
                "  workflow_dispatch:\n",
                "  pull_request_target:\n  workflow_dispatch:\n",
            ),
            "push trigger": (
                "  workflow_dispatch:\n",
                "  push:\n  workflow_dispatch:\n",
            ),
            "additional workflow input": (
                "      parent_head_sha:\n",
                "      policy_profile:\n        required: true\n        type: string\n      parent_head_sha:\n",
            ),
            "dynamic variant input": (
                "      parent_head_sha:\n",
                "      matrix_variant:\n        required: true\n        type: string\n      parent_head_sha:\n",
            ),
            "target checkout": (
                "          ref: ${{ github.sha }}",
                "          ref: ${{ inputs.parent_head_sha }}",
            ),
            "mutable caller checkout": (
                "          ref: ${{ github.sha }}",
                "          ref: master",
            ),
            "missing caller checkout head assertion": (
                '          test "$(git rev-parse HEAD)" = "$GITHUB_SHA"\n',
                "",
            ),
            "target execution": (
                "          set -euo pipefail",
                "          set -euo pipefail\n          python3 \"$TARGET_PARENT_SHA\"",
            ),
            "caller-selected manifest path": (
                '            --with-crs-run-id "$WITH_CRS_RUN_ID"',
                '            --with-crs-run-id "$WITH_CRS_RUN_ID" \\\n            --output-root "$RUNNER_TEMP/unsafe"',
            ),
            "caller-selected evidence path": (
                "          python3 ci/runtime/broker/protected_nginx_broker_caller.py verify-evidence \\\n",
                "          python3 ci/runtime/broker/protected_nginx_broker_caller.py verify-evidence \\\n"
                '            --no-crs-directory "$RUNNER_TEMP/unsafe" \\\n',
            ),
            "write permission": (
                "    permissions:\n      contents: read",
                "    permissions:\n      contents: write",
            ),
            "secret reference": (
                "          set -euo pipefail",
                "          set -euo pipefail\n          printf '%s\\n' \"${{ secrets.CALLER_SECRET }}\"",
            ),
            "sudo in caller": (
                "          set -euo pipefail",
                "          set -euo pipefail\n          sudo true",
            ),
            "result masks a failed broker": (
                '"$NO_CRS_RESULT" != success',
                '"$NO_CRS_RESULT" = success',
            ),
        }
        for name, (original, replacement) in mutations.items():
            with self.subTest(name=name):
                self.assertIn(original, text)
                mutated = text.replace(original, replacement, 1)
                self.assertNotEqual(protected_nginx_broker_caller_errors(mutated), [])

    def test_untrusted_pull_request_model(self) -> None:
        sarif_write_jobs = {
            key for key, value in EXPECTED_WRITE_PERMISSIONS.items() if value.get("security-events") == "write"
        }
        for path in self.workflow_paths():
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("pull_request_target:", text, path.name)
            self.assertNotIn("workflow_run:", text, path.name)
            if not re.search(r"(?m)^\s*pull_request:", text):
                continue
            if path.name == "sonarqube.yml":
                self.assertEqual(sonar_pr_secret_errors(text), [], path.name)
            elif path.name == "sonar-native-security.yml":
                self.assertEqual(sonar_native_pr_secret_errors(text), [], path.name)
            else:
                self.assertNotIn("secrets.", text, path.name)
            for job_name, job in job_blocks(text).items():
                permissions = job_permissions(job)
                if not any(value == "write" for value in permissions.values()):
                    continue
                self.assertIn((path.name, job_name), sarif_write_jobs, f"{path.name}:{job_name}")
                self.assertEqual(
                    permissions,
                    {"contents": "read", "security-events": "write"},
                    f"{path.name}:{job_name}",
                )
                if path.name == "ci-security-scorecard.yml":
                    self.assertIn("github.event_name != 'pull_request'", job)

    def test_sonar_secret_contract_rejects_fork_guard_bypass(self) -> None:
        text = self.workflow("sonarqube.yml")
        unsafe = text.replace(
            "github.repository == 'Easton97-Jens/ModSecurity-conector' &&",
            "true || github.repository == 'Easton97-Jens/ModSecurity-conector' &&",
            1,
        )
        self.assertNotEqual(sonar_pr_secret_errors(unsafe), [])

    def test_native_sonar_workflow_meets_closed_contract(self) -> None:
        self.assertEqual(sonar_native_pr_secret_errors(self.workflow("sonar-native-security.yml")), [])

    def test_native_sonar_workflow_rejects_contract_mutations(self) -> None:
        text = self.workflow("sonar-native-security.yml")
        mutations = [
            ("fork guard", "github.repository == 'Easton97-Jens/ModSecurity-conector' &&", "true || github.repository == 'Easton97-Jens/ModSecurity-conector' &&"),
            ("second checkout", "      - name: Set up canonical Python", "      - uses: " + locked_action_reference_with_version("actions/checkout") + "\n        with:\n          ref: master\n          persist-credentials: false\n      - name: Set up canonical Python"),
            ("inserted git checkout", "          set -euo pipefail", "          set -euo pipefail\n          git checkout master"),
            ("different preparation wrapper", "prepare-sonar-native-ci.py analyze", "unreviewed-native-wrapper.py analyze"),
            ("global token", "permissions: {}", "env:\n  SONAR_TOKEN: '${{ secrets.SONAR_TOKEN }}'\npermissions: {}"),
            ("global source environment", "env:\n  NATIVE_CI_ROOT:", "env:\n  BASH_ENV: /unreviewed.sh\n  NATIVE_CI_ROOT:"),
            ("write permission", "      contents: read", "      contents: write"),
            ("wrong source revision", "ref: ${{ github.event.pull_request.head.sha || github.sha }}", "ref: master"),
            ("persisted credentials", "persist-credentials: false", "persist-credentials: true"),
            ("unexpected recursive submodules", "submodules: false", "submodules: recursive"),
            ("different project", "project: Easton97-Jens_ModSecurity-conector_native_haproxy_htx", "project: Easton97-Jens_ModSecurity-conector"),
            ("different target", "target: haproxy-htx", "target: apache-native-module"),
            ("different concurrency", "max-parallel: 2", "max-parallel: 11"),
            ("masked native failure", "    needs: sdk", "    continue-on-error: true\n    needs: sdk"),
            ("scanner argument injection", "-Dsonar.projectKey=${{ matrix.project }}", "-Dsonar.projectKey=${{ matrix.project }} -Dsonar.cfamily.taintAnalysis=false"),
            ("wrong SCM identity", "-Dsonar.scm.revision=${{ github.event.pull_request.head.sha || github.sha }}", "-Dsonar.scm.revision=master"),
            ("token in shell", "          umask 077", "          umask 077\n          echo '${{ secrets.SONAR_TOKEN }}'"),
            ("different scanner Action", "uses: SonarSource/sonarqube-scan-action@", "uses: other/scanner@"),
            ("source-controlled shell default", "    shell: bash", "    shell: python"),
            ("privileged event", "  pull_request:", "  pull_request_target:"),
        ]
        for name, original, replacement in mutations:
            with self.subTest(name=name):
                self.assertIn(original, text)
                self.assertNotEqual(sonar_native_pr_secret_errors(text.replace(original, replacement, 1)), [])

    def test_native_sonar_action_updates_require_matching_canonical_lock(self) -> None:
        text = self.workflow("sonar-native-security.yml")
        original = locked_action_reference_with_version("SonarSource/sonarqube-scan-action")
        replacement = "SonarSource/sonarqube-scan-action@" + "a" * 40 + " # v99.0.0"
        self.assertNotEqual(sonar_native_pr_secret_errors(text.replace(original, replacement)), [])
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "security-tools.lock.yml"
            value = yaml.safe_load(LOCK_PATH.read_text())
            value["pinned_actions"]["SonarSource/sonarqube-scan-action"].update({"commit_sha": "a" * 40, "version": "v99.0.0"})
            lock.write_text(yaml.safe_dump(value))
            from unittest.mock import patch
            with patch.dict(globals(), LOCK_PATH=lock):
                self.assertEqual(sonar_native_pr_secret_errors(text.replace(original, replacement)), [])
                self.assertNotEqual(sonar_native_pr_secret_errors(text), [])

    def test_native_sonar_retry_reuses_successful_sdk_identity(self) -> None:
        text = self.workflow("sonar-native-security.yml")
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        sdk, native = workflow["jobs"]["sdk"], workflow["jobs"]["native"]
        self.assertEqual(sdk["outputs"], {
            "artifact_id": "${{ steps.upload-sdk.outputs.artifact-id }}",
            "producer_root": "${{ steps.prepare-sdk.outputs.producer_root }}",
        })
        prepare = next(step for step in sdk["steps"] if step.get("id") == "prepare-sdk")
        self.assertIn('printf \'producer_root=%s\\n\' "$NATIVE_CI_ROOT" >> "$GITHUB_OUTPUT"', prepare["run"])
        root_template = workflow["env"]["NATIVE_CI_ROOT"].replace("${{ github.run_id }}", "123")
        successful_sdk = {"producer_root": root_template.replace("${{ github.run_attempt }}", "1"),
                          "artifact_id": "456"}
        retry_global_root = root_template.replace("${{ github.run_attempt }}", "2")
        download = next(step for step in native["steps"] if str(step.get("uses", "")).startswith("actions/download-artifact@"))
        references = {"root": native["env"]["NATIVE_CI_ROOT"], "artifact": download["with"]["artifact-ids"]}
        resolved = {name: successful_sdk[expression.removeprefix("${{ needs.sdk.outputs.").removesuffix(" }}")]
                    for name, expression in references.items()}
        self.assertEqual(resolved, {"root": successful_sdk["producer_root"], "artifact": "456"})
        self.assertNotEqual(resolved["root"], retry_global_root)
        self.assertEqual(download["with"]["merge-multiple"], "true")
        self.assertNotIn("name", download["with"])
        self.assertNotIn("run-id", download["with"])
        self.assertEqual(sonar_native_pr_secret_errors(text), [])

    def test_sonar_secret_contract_rejects_global_token(self) -> None:
        text = self.workflow("sonarqube.yml")
        unsafe = text.replace("permissions: {}", "env:\n  SONAR_TOKEN: '${{ secrets.SONAR_TOKEN }}'\n\npermissions: {}", 1)
        self.assertNotEqual(sonar_pr_secret_errors(unsafe), [])

    def test_sonar_secret_contract_rejects_secret_in_shell(self) -> None:
        text = self.workflow("sonarqube.yml")
        unsafe = text.replace("          set -euo pipefail", "          set -euo pipefail\n          echo '${{ secrets.SONAR_TOKEN }}'", 1)
        self.assertNotEqual(sonar_pr_secret_errors(unsafe), [])

    def test_sonar_secret_contract_rejects_other_action(self) -> None:
        text = self.workflow("sonarqube.yml")
        unsafe = text.replace("uses: SonarSource/sonarqube-scan-action@", "uses: unknown/scanner@", 1)
        self.assertNotEqual(sonar_pr_secret_errors(unsafe), [])

    def test_sonar_standard_matrix_keeps_full_parent_scope(self) -> None:
        text = self.workflow("sonarqube.yml")
        self.assertEqual(sonar_pr_secret_errors(text), [])
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        scanner = next(step for step in workflow["jobs"]["analysis"]["steps"] if step.get("id") == "scan")
        args = scanner["with"]["args"]
        self.assertIn("-Dsonar.projectKey=${{ matrix.project }}", args)
        self.assertIn("-Dsonar.cfamily.reportingCppStandardOverride=c++${{ matrix.cpp }}", args)
        self.assertNotRegex(args, r"-D(?:sonar\.(?:sources|tests|inclusions|exclusions)|project\.settings)=")
        self.assertNotIn("projectBaseDir", scanner["with"])
        self.assertNotIn("run-sonar-coverage.py", text)
        self.assertNotIn("ON_DEMAND_TESTS", text)
        self.assertNotIn("unittest", text)
        self.assertNotIn("go test", text)
        self.assertNotIn("check-common-helpers.sh", text)
        self.assertIn("ci/checks/analysis/check-sonar-scope.py", text)
        self.assertIn("-Dsonar.qualitygate.wait=true", args)

    def test_sonar_standard_matrix_rejects_decisive_higher_standards(self) -> None:
        text = self.workflow("sonarqube.yml")
        self.assertNotEqual(sonar_pr_secret_errors(text.replace("advisory: true", "advisory: false", 1)), [])

    def test_sonar_secret_contract_rejects_alternate_secret_access(self) -> None:
        text = self.workflow("sonarqube.yml")
        for expression in ("secrets['OTHER']", "secrets [ 'OTHER' ]", "toJSON(secrets)"):
            with self.subTest(expression=expression):
                unsafe = text.replace(
                    "          set -euo pipefail",
                    "          set -euo pipefail\n          echo '${{ " + expression + " }}'",
                    1,
                )
                self.assertNotEqual(sonar_pr_secret_errors(unsafe), [])

    def test_cleanup_jobs_do_not_checkout_or_execute_project_code(self) -> None:
        for workflow_name in ("cleanup-artifacts.yml", "test-full-smoke-sequential.yml"):
            job = self.jobs(workflow_name)["cleanup-artifacts"]
            self.assertEqual(job_permissions(job), {"actions": "write"}, workflow_name)
            self.assertEqual(checkout_step_blocks(job), [], workflow_name)
            self.assertNotIn("run:", job, workflow_name)

    def test_ci_security_contracts_run_the_local_submodule_git_regressions(self) -> None:
        workflow = self.workflow("ci-security-workflow-lint.yml")
        makefile = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
        contract_target = makefile.partition("check-ci-security-contract:")[2].partition(
            "\n\n"
        )[0]
        for module in SUBMODULE_LOCAL_GIT_CONTRACT_TESTS:
            with self.subTest(module=module):
                self.assertIn(module, workflow)
                self.assertIn(module, contract_target)
        self.assertTrue((ROOT / SUBMODULE_CANDIDATE_STATE_HELPER).is_file())

    def test_submodule_namespace_failure_keeps_diagnostics_status_and_cleanup(self) -> None:
        workflow = self.workflow("update-submodules.yml")
        steps = yaml.safe_load(workflow)["jobs"]["validate-submodule-update"]["steps"]
        candidate_step = next(step for step in steps
                              if step.get("name") == "Run quick check in the private read-only namespace")
        cases = (("success", 0, READONLY_SUBMODULE_NAMESPACE_COMPLETE, 0),
                 ("candidate failure", 17, "native fixture failed\n" + READONLY_SUBMODULE_NAMESPACE_COMPLETE, 17),
                 ("missing completion", 0, "candidate stopped without completion", 1))
        for name, candidate_status, output, expected_status in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                mock_bin = root / "bin"; mock_bin.mkdir()
                namespace_root = root / "namespace parents"; namespace_root.mkdir()
                created_paths = root / "created-paths.log"
                sudo_log = root / "sudo.log"
                mock_sudo = mock_bin / "sudo"
                mock_sudo.write_text("\n".join((
                    "#!/bin/sh", "set -eu", 'printf \'%s\\n\' "$*" >> "$MOCK_SUDO_LOG"',
                    'test "$1" = -n', "shift", 'case "$1" in',
                    "  mktemp)",
                    '    path="$(/usr/bin/mktemp -d "$MOCK_NAMESPACE_ROOT/namespace.XXXXXX")"',
                    '    printf \'%s\\n\' "$path" >> "$MOCK_CREATED_PATHS"',
                    '    printf \'%s\\n\' "$path"', "    ;;",
                    "  chown|chmod) exit 0 ;;",
                    '  rmdir) shift; exec /usr/bin/rmdir "$@" ;;',
                    "  python3)",
                    '    test "$2" = ci/tools/run-readonly-submodule-validation-namespace.py',
                    '    printf \'%s\\n\' "$MOCK_NAMESPACE_STDOUT"',
                    '    printf \'%s\\n\' "namespace-stderr-diagnostic" >&2',
                    '    exit "$MOCK_NAMESPACE_STATUS" ;;',
                    '  *) echo "unexpected mocked sudo command: $*" >&2; exit 99 ;;',
                    "esac", "",
                )), encoding="utf-8")
                mock_sudo.chmod(0o700)
                environment = {
                    **os.environ,
                    "PATH": str(mock_bin) + os.pathsep + os.defpath,
                    "MOCK_SUDO_LOG": str(sudo_log), "MOCK_CREATED_PATHS": str(created_paths),
                    "MOCK_NAMESPACE_ROOT": str(namespace_root), "MOCK_NAMESPACE_STDOUT": output,
                    "MOCK_NAMESPACE_STATUS": str(candidate_status),
                    "GITHUB_WORKSPACE": str(root / "source space"),
                    "SUBMODULE_PATH": "modules/ModSecurity-test-Framework",
                    "VALIDATION_WRITE_ROOT": str(root / "guard space"),
                    "EXPECTED_PYTHON": "/selected runtime/bin/python",
                }
                environment.pop("BASH_ENV", None)
                result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-ceu", candidate_step["run"]],
                                        env=environment, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, expected_status, result.stderr)
                self.assertIn(output, result.stdout)
                self.assertIn("namespace-stderr-diagnostic", result.stderr)
                self.assertTrue(created_paths.is_file(), result.stderr)
                created = Path(created_paths.read_text(encoding="utf-8").splitlines()[-1])
                self.assertFalse(created.exists())
                self.assertIn(f"rmdir -- {created}", sudo_log.read_text(encoding="utf-8"))

    def test_update_submodules_separates_validation_from_publishing(self) -> None:
        workflow = self.workflow("update-submodules.yml")
        jobs = job_blocks(workflow)
        self.assertEqual(
            set(jobs),
            {
                "resolve-submodule-update",
                "validate-submodule-update",
                "create-submodule-update-pr",
                "report-submodule-update-outcome",
            },
        )
        resolver = jobs["resolve-submodule-update"]
        validator = jobs["validate-submodule-update"]
        publisher = jobs["create-submodule-update-pr"]
        normalized_publisher = normalize_shell_script(publisher)
        outcome = jobs["report-submodule-update-outcome"]

        self.assertEqual(job_permissions(resolver), {"contents": "read"})
        self.assertEqual(job_permissions(validator), {"contents": "read"})
        self.assertEqual(job_permissions(publisher), {"contents": "read"})
        self.assertEqual(job_permissions(outcome), {"contents": "read"})
        self.assertEqual(job_if_expression(outcome), "always()")
        self.assertEqual(update_submodule_validate_only_errors(workflow), [])
        self.assertEqual(submodule_publisher_token_errors(workflow), [])
        self.assertEqual(job_if_expression(resolver), SUBMODULE_RESOLVER_GATE)
        self.assertEqual(resolver.count(SUBMODULE_VALIDATE_ONLY_CHECKOUT_REF), 1)
        self.assertEqual(validator.count(SUBMODULE_VALIDATE_ONLY_CHECKOUT_REF), 1)
        self.assertIn("github.ref == 'refs/heads/master'", resolver)
        self.assertIn("github.event.repository.default_branch == 'master'", resolver)
        self.assertIn("github.event.repository.fork == false", resolver)
        self.assertIn("remote_ref_count", resolver)
        self.assertIn('if [ "$remote_ref_count" != "1" ]; then', resolver)
        self.assertIn('if [ "$candidate_ref" != "$SUBMODULE_REF" ]; then', resolver)
        self.assertIn("Resolved submodule revision is not a full SHA-1", resolver)
        self.assertIn("Current gitlink is not a full SHA-1", resolver)
        self.assertIn('if [ "$candidate_sha" = "$current_sha" ]; then', resolver)
        self.assertIn("changed=false", resolver)
        self.assertIn("changed=true", resolver)
        self.assertIn("Current Parent tree does not contain exactly one submodule entry", resolver)
        self.assertIn("candidate_sha", resolver)
        self.assertIn("current_sha", resolver)
        self.assertIn("resolver_status=resolved", resolver)

        self.assertIn("needs: resolve-submodule-update", validator)
        self.assertEqual(
            job_if_expression(validator),
            SUBMODULE_VALIDATOR_GATE,
        )
        self.assertIn("submodules: false", validator)
        self.assertNotIn("submodules: recursive", validator)
        self.assertIn(READONLY_SUBMODULE_NAMESPACE_CALL, normalize_shell_script(validator))
        self.assertIn("remote get-url origin", validator)
        self.assertIn("merge-base --is-ancestor", validator)
        self.assertIn("checkout --detach", validator)
        self.assertIn(
            'git -c protocol.file.allow=never submodule update --init -- "$SUBMODULE_PATH"',
            validator,
        )
        self.assertNotIn("submodule update --init --recursive", validator)
        self.assertEqual(validator.count("Validate Framework component-pin data contract"), 1)
        self.assertIn("sync-framework-component-versions.py", validator)
        self.assertIn("--validate", validator)
        self.assertIn('--framework-sha "$CANDIDATE_SHA"', validator)
        self.assertIn("verify-framework-candidate-contract.py", validator)
        self.assertIn('--candidate-sha "$CANDIDATE_SHA"', validator)
        self.assertIn(
            '--expected-parent-framework-sha "$CURRENT_GITLINK_SHA"', validator
        )
        self.assertIn('"$CANDIDATE_SHA:ci/lib/common.sh"', validator)
        self.assertIn('git -c core.hooksPath=/dev/null -C "$SUBMODULE_PATH" show', validator)
        for forbidden in (
            'source "$framework_common"',
            '. "$framework_common"',
            'bash "$framework_common"',
            'sh "$framework_common"',
            'eval "$framework_common"',
            'python3 "$framework_common"',
        ):
            self.assertNotIn(forbidden, validator)
        component_pin_validator = validator.partition(
            "Prepare dedicated read-only candidate sandbox"
        )[0]
        self.assertNotIn("continue-on-error", component_pin_validator)
        self.assertLess(
            workflow.index("Validate Framework component-pin data contract"),
            workflow.index("Prepare dedicated read-only candidate sandbox"),
        )
        self.assertIn(SUBMODULE_CANDIDATE_BASELINE_CALL, normalize_shell_script(validator))
        self.assertEqual(normalize_shell_script(validator).count(SUBMODULE_CANDIDATE_STATE_CALL), 2)
        self.assertNotIn("status --porcelain", validator)
        self.assertNotIn("grep -v", validator)
        self.assertNotIn("git reset --hard", validator)
        self.assertNotIn("git clean", validator)
        self.assertNotIn("|| true", validator)
        self.assertTrue((ROOT / SUBMODULE_CANDIDATE_STATE_HELPER).is_file())
        dependency_lock = (
            source_path('ci/requirements/update-submodules-validation-linux-x86_64.txt', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn("PyYAML==6.0.3", dependency_lock)
        self.assertIn(
            "--hash=sha256:c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5",
            dependency_lock,
        )
        self.assertNotIn("PyYAML>=", dependency_lock)
        self.assertIn("EXPECTED_PYTHON: ${{ steps.setup-python.outputs.python-path }}", validator)
        self.assertNotIn("GH_TOKEN", validator)
        self.assertNotIn("secrets.", validator)
        self.assertEqual(readonly_submodule_validator_errors(validator), [])
        sandbox_helper = (
            source_path('ci/tools/prepare-readonly-submodule-validation-sandbox.py', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertEqual(readonly_submodule_sandbox_helper_errors(sandbox_helper), [])
        sandbox_helper_mutations = {
            "source locking returns": (
                "def _make_external_root",
                "def _lock_tree(root: Path) -> None:\n"
                "    for path, _relative, metadata in _walk_tree(root):\n"
                "        os.chown(path, 0, 0, follow_symlinks=False)\n"
                "        os.chmod(path, stat.S_IMODE(metadata.st_mode) & ~0o022)\n\n\n"
                "def _make_external_root",
            ),
            "nested source mount rejection removed": (
                "_reject_nested_source_mounts(source)",
                "_nested_source_mounts_not_checked(source)",
            ),
            "cleanup loses descriptor traversal": (
                "_open_existing_directory_path(temporary)",
                "os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)",
            ),
        }
        for name, (original, replacement) in sandbox_helper_mutations.items():
            with self.subTest(sandbox_helper_mutation=name):
                self.assertIn(original, sandbox_helper)
                mutated = sandbox_helper.replace(original, replacement, 1)
                self.assertNotEqual(readonly_submodule_sandbox_helper_errors(mutated), [])

        candidate_state_mutations = {
            "missing immutable Parent baseline": (
                "capture-parent-baseline",
                "capture-parent-baseline-bypassed",
            ),
            "candidate state validated only once": (
                "validate \\\n            --parent-root",
                "validate-bypassed \\\n            --parent-root",
            ),
            "broad Parent status check restored": (
                "git -c core.hooksPath=/dev/null diff --check",
                "git status --porcelain --untracked-files=all\n          git -c core.hooksPath=/dev/null diff --check",
            ),
        }
        for name, (original, replacement) in candidate_state_mutations.items():
            with self.subTest(candidate_state_mutation=name):
                self.assertIn(original, validator)
                mutated = validator.replace(original, replacement, 1)
                self.assertNotEqual(readonly_submodule_validator_errors(mutated), [])

        """Run the exact workflow prelude with a test-local sudo implementation."""
        workflow_payload = yaml.safe_load(self.workflow("update-submodules.yml"))
        steps = workflow_payload["jobs"]["validate-submodule-update"]["steps"]
        native_name = "Install selected Apache native lifecycle prerequisites"
        native_step = next(step for step in steps if step["name"] == native_name)
        self.assertEqual(set(native_step), {"name", "run"})
        self.assertEqual(normalize_shell_script(native_step["run"]),
                         "set -euo pipefail sudo apt-get update sudo apt-get install "
                         "--no-install-recommends --yes build-essential apache2-dev libmodsecurity-dev")
        dependency_name = "Prepare reviewed Python dependency before runtime protection"
        dependency_step = next(step for step in steps if step["name"] == dependency_name)
        self.assertEqual(set(dependency_step), {"name", "run"})
        self.assertEqual(normalize_shell_script(dependency_step["run"]),
                         "set -euo pipefail python3 ci/tools/install-ci-dependencies.py --ci-toolcache "
                         "--framework-lock modules/ModSecurity-test-Framework/requirements-ci.lock "
                         "python3 -m pip check")
        names = [step.get("name") for step in steps]
        self.assertLess(names.index("Verify Python interpreter contract"), names.index(native_name))
        self.assertLess(names.index(native_name), names.index("Capture immutable Parent validation baseline"))
        self.assertLess(names.index("Validate Framework component-pin data contract"),
                        names.index(dependency_name))
        self.assertLess(names.index(dependency_name), names.index("Create private read-only candidate guard"))
        candidate_step = next(
            step for step in steps if step["name"] == "Run quick check in the private read-only namespace"
        )
        prelude, separator, _candidate = candidate_step["run"].partition("namespace_output=")
        expected_prelude = """\
set -euo pipefail
namespace_parent=""
cleanup_namespace_parent() {
  namespace_status=$?
  if [ -n "$namespace_parent" ]; then
    sudo -n rmdir -- "$namespace_parent" || {
      echo "Unable to remove readonly namespace parent" >&2
      return 1
    }
  fi
  return "$namespace_status"
}
trap cleanup_namespace_parent EXIT
namespace_parent="$(sudo -n mktemp -d /tmp/modsecurity-readonly-namespace.XXXXXX)"
sudo -n chown root:modsecurity-validator "$namespace_parent"
sudo -n chmod 0750 "$namespace_parent"
namespace_status=0
"""
        self.assertTrue(separator)
        self.assertEqual(prelude, expected_prelude)
        self.assertNotIn("run-readonly-submodule-validation-namespace.py", prelude)

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            mock_bin = temporary_root / "bin"; mock_bin.mkdir()
            namespace_root = temporary_root / "namespace-parents"; namespace_root.mkdir()
            sudo_log = temporary_root / "sudo.log"
            created_paths = temporary_root / "created-paths.log"
            mock_sudo = mock_bin / "sudo"
            mock_sudo.write_text(
                "\n".join(
                    (
                        "#!/bin/sh", "set -eu", "printf '%s\\n' \"$*\" >> \"$MOCK_SUDO_LOG\"",
                        "test \"$1\" = -n", "shift", "case \"$1\" in",
                        "  mktemp)",
                        "    path=\"$(/usr/bin/mktemp -d \"$MOCK_NAMESPACE_ROOT/namespace.XXXXXX\")\"",
                        "    printf '%s\\n' \"$path\" >> \"$MOCK_CREATED_PATHS\"",
                        "    printf '%s\\n' \"$path\"", "    ;;",
                        "  chown|chmod) exit 0 ;;", "  rmdir)", "    shift",
                        "    if [ \"${MOCK_RMDIR_FAILURE:-0}\" = 1 ]; then exit 73; fi",
                        "    exec /usr/bin/rmdir \"$@\"", "    ;;",
                        "  *) echo \"unexpected mocked sudo command: $*\" >&2; exit 99 ;;", "esac", "",
                    )
                ),
                encoding="utf-8",
            )
            mock_sudo.chmod(0o700)

            def execute(candidate_status: int, *, rmdir_failure: bool = False) -> tuple[subprocess.CompletedProcess[str], Path]:
                environment = {
                    **os.environ,
                    "PATH": f"{mock_bin}:{os.environ['PATH']}",
                    "MOCK_SUDO_LOG": str(sudo_log),
                    "MOCK_CREATED_PATHS": str(created_paths),
                    "MOCK_NAMESPACE_ROOT": str(namespace_root),
                    "MOCK_RMDIR_FAILURE": "1" if rmdir_failure else "0",
                    "CANDIDATE_STATUS": str(candidate_status),
                }
                environment.pop("BASH_ENV", None)
                result = subprocess.run(
                    ["/bin/bash", "-ceu", "\n".join((expected_prelude, 'exit "$CANDIDATE_STATUS"', ""))],
                    text=True, capture_output=True, env=environment, check=False,
                )
                if not created_paths.exists():
                    self.fail(result.stderr)
                created = Path(created_paths.read_text(encoding="utf-8").splitlines()[-1])
                return result, created

            success, success_parent = execute(0)
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertFalse(success_parent.exists())

            candidate_failure, failed_parent = execute(47)
            self.assertEqual(candidate_failure.returncode, 47, candidate_failure.stderr)
            self.assertFalse(failed_parent.exists())

            cleanup_failure, retained_parent = execute(0, rmdir_failure=True)
            try:
                self.assertNotEqual(cleanup_failure.returncode, 0)
                self.assertTrue(retained_parent.is_dir())
            finally:
                if retained_parent.exists():
                    retained_parent.rmdir()

            log = sudo_log.read_text(encoding="utf-8")
            self.assertIn(f"rmdir -- {success_parent}", log)
            self.assertIn(f"rmdir -- {failed_parent}", log)
            self.assertIn(f"rmdir -- {retained_parent}", log)
            self.assertNotIn("rm -rf", log)
        namespace_runner = (
            source_path('ci/tools/run-readonly-submodule-validation-namespace.py', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertEqual(readonly_namespace_runner_errors(namespace_runner), [])
        namespace_mutations = {
            "namespace loses PID isolation": (
                "CLONE_NEWNS | CLONE_NEWPID",
                "CLONE_NEWNS",
            ),
            "namespace propagation is not private": (
                '_mount(None, Path("/"), MS_REC | MS_PRIVATE)',
                '_mount(None, Path("/"), MS_REC)',
            ),
            "candidate can gain new privileges": (
                "if LIBC.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:",
                "if False:",
            ),
            "candidate does not prove no-new-privileges": (
                "NoNewPrivs:",
                "NoNewPrivileges:",
            ),
            "source is recursively bound": (
                "_mount(str(source), source_view, MS_BIND)",
                "_mount(str(source), source_view, MS_REC | MS_BIND)",
            ),
            "nested source mounts are accepted": (
                "_reject_nested_source_mounts(source)",
                "_nested_source_mounts_not_checked(source)",
            ),
            "source loses read-only remount": (
                "_mount(None, source_view, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)",
                "_mount(None, source_view, MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV)",
            ),
            "output loses device restriction": (
                "_mount(None, external_view, MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV)",
                "_mount(None, external_view, MS_BIND | MS_REMOUNT | MS_NOSUID)",
            ),
            "candidate retains root identity": (
                "os.setgroups([]); os.setgid(gid); os.setuid(uid); os.chdir(source)",
                "os.chdir(source)",
            ),
            "candidate loses hosted-run classification": (
                '"GITHUB_ACTIONS": "true"',
                '"GITHUB_ACTIONS": "false"',
            ),
            "namespace uses lazy cleanup": (
                "os.rmdir(path)",
                "MNT_DETACH",
            ),
            "namespace accepts a public parent": (
                "namespace parent must be root:validator mode 0750",
                "namespace parent may be public",
            ),
            "namespace mount root loses validator traversal": (
                "os.fchmod(descriptor, 0o750)",
                "os.mkdir(path, mode=0o700)",
            ),
            "namespace restores unsafe Python chmod": (
                "os.fchown(descriptor, 0, validator_gid)",
                "os.fchown(descriptor, 0, validator_gid)\n            os.chmod(path, 0o755)",
            ),
            "namespace hardcodes the public temporary directory": (
                "namespace_ancestor = namespace_parent.parent",
                'namespace_ancestor = Path("/tmp")',
            ),
            "namespace changes the process umask": (
                "os.fchmod(descriptor, 0o750)",
                "os.umask(0)\n            os.fchmod(descriptor, 0o750)",
            ),
            "namespace catches process-control exceptions": (
                "except Exception as error:",
                "except BaseException as error:",
            ),
        }
        for name, (original, replacement) in namespace_mutations.items():
            with self.subTest(name=name):
                self.assertIn(original, namespace_runner)
                mutated_runner = namespace_runner.replace(original, replacement, 1)
                self.assertNotEqual(readonly_namespace_runner_errors(mutated_runner), [])

        proc_match = re.search(
            r'''_mount\(\s*["']proc["']\s*,\s*layout\.proc\s*,\s*'''
            r"MS_RDONLY\s*\|\s*MS_NOSUID\s*\|\s*MS_NODEV\s*\|\s*MS_NOEXEC"
            r'''\s*,\s*["']proc["']\s*\)''',
            namespace_runner,
        )
        self.assertIsNotNone(proc_match)
        assert proc_match is not None
        proc_mount = proc_match.group(0)
        jail_mutations = {
            "private procfs constant is mutable to another target": (
                'PROCFS_TARGET = Path("/proc")',
                'PROCFS_TARGET = Path("/proc-unsafe")',
            ),
            "private procfs is missing": (proc_mount, proc_mount.replace('"proc"', '"none"', 1)),
            "private procfs has executable flags": (proc_mount, proc_mount.replace("| MS_NOEXEC", "", 1)),
            "private jail root is missing": (
                '_mount("tmpfs", mount_root, MS_NOSUID | MS_NODEV | MS_NOEXEC, "tmpfs")',
                "pass",
            ),
            "candidate skips chroot": ('os.chroot(".")', "pass"),
            "candidate keeps inherited descriptors": (
                "_close_unapproved_descriptors({0, 1, 2, proc_ready_write})",
                "pass",
            ),
            "candidate can retain host temp paths": (
                "for target in /tmp /var /home /root /run /sys /dev/shm",
                "for target in /source",
            ),
            "parent skips jail teardown": ("_teardown_jail_layout(layout)", "pass"),
        }
        for name, (original, replacement) in jail_mutations.items():
            with self.subTest(name=name):
                self.assertIn(original, namespace_runner)
                mutated_runner = namespace_runner.replace(original, replacement, 1)
                self.assertNotEqual(readonly_namespace_runner_errors(mutated_runner), [])
        self.assertLess(
            validator.index("Create private read-only candidate guard"),
            validator.index("Prepare dedicated read-only candidate sandbox"),
        )
        self.assertLess(
            validator.index("Prepare dedicated read-only candidate sandbox"),
            validator.index("Run quick check in the private read-only namespace"),
        )
        self.assertLess(
            validator.index("Run quick check in the private read-only namespace"),
            validator.index("Verify candidate source inventory and external outputs"),
        )
        self.assertLess(
            validator.index("Check out the resolved descendant revision"),
            validator.index("Prepare dedicated read-only candidate sandbox"),
        )
        self.assertLess(
            validator.index("Enforce isolated candidate result after verification"),
            validator.index("Clean up private read-only candidate guard"),
        )
        self.assertIn(READONLY_SUBMODULE_SANDBOX_CALL, normalize_shell_script(validator))
        self.assertIn(READONLY_SUBMODULE_WRITE_ROOT, validator)
        self.assertIn(READONLY_SUBMODULE_EXTERNAL_ROOT, validator)
        self.assertNotIn("setfacl", validator)
        self.assertNotIn("getfacl", validator)
        self.assertNotIn("sudo -n -u modsecurity-validator", validator)
        self.assertNotIn("sudo -n python3 ci/tools/validate-submodule-candidate-state.py", validator)
        self.assertNotIn("sudo -n git -c core.hooksPath=/dev/null diff --check", validator)

        validator_mutations = {
            "namespace helper removed": (
                "run-readonly-submodule-validation-namespace.py",
                "run-readonly-submodule-validation-namespace.removed.py",
            ),
            "namespace helper loses the physical guard root": (
                '--write-root "$VALIDATION_WRITE_ROOT"',
                '--write-root /tmp/validator-guard',
            ),
            "namespace helper loses the physical external root": (
                '--external-root "$VALIDATION_WRITE_ROOT/external"',
                '--external-root /tmp/validator-output',
            ),
            "namespace helper loses the unprivileged user": (
                "--validator-user modsecurity-validator",
                "--validator-user root",
            ),
            "namespace helper loses its private mount parent": (
                '--namespace-parent "$namespace_parent"',
                "--namespace-parent /tmp",
            ),
            "namespace parent is not trusted root-created storage": (
                'namespace_parent="$(sudo -n mktemp -d /tmp/modsecurity-readonly-namespace.XXXXXX)"',
                'namespace_parent="/tmp/modsecurity-readonly-namespace"',
            ),
            "namespace parent cleanup becomes recursive": (
                'sudo -n rmdir -- "$namespace_parent"',
                'sudo -n rm -rf -- "$namespace_parent"',
            ),
            "namespace completion marker is not required": (
                READONLY_SUBMODULE_NAMESPACE_COMPLETE,
                "READONLY_SUBMODULE_VALIDATION_NAMESPACE_NOT_COMPLETE",
            ),
            "post-candidate source verification removed": (
                "Verify candidate source inventory and external outputs",
                "Candidate verification removed",
            ),
            "inventory verification disabled": (
                "--verify",
                "--inspect",
            ),
            "verification no longer runs after candidate failure": (
                "- name: Verify candidate source inventory and external outputs\n"
                "        " + READONLY_SUBMODULE_VERIFY_GATE,
                "- name: Verify candidate source inventory and external outputs\n"
                "        if: ${{ success() }}",
            ),
            "candidate result is not enforced after verification": (
                'test "$CANDIDATE_RESULT" = success',
                "true",
            ),
            "private guard cleanup is no longer unconditional": (
                READONLY_SUBMODULE_CLEANUP_GATE,
                "if: ${{ success() }}",
            ),
            "private guard cleanup is removed": (
                "Clean up private read-only candidate guard",
                "Private guard cleanup removed",
            ),
            "private guard cleanup loses its fixed prefix contract": (
                "--cleanup",
                "--cleanup-disabled",
            ),
            "workflow regains ACL mutation": (
                "printf 'write_root=%s\\n' \"$write_root\" >> \"$GITHUB_OUTPUT\"",
                "printf 'write_root=%s\\n' \"$write_root\" >> \"$GITHUB_OUTPUT\"\n"
                '          sudo -n setfacl -m "u:modsecurity-validator:--x" -- "$RUNNER_TEMP"',
            ),
        }
        for name, (original, replacement) in validator_mutations.items():
            with self.subTest(name=name):
                self.assertIn(original, validator)
                mutated = validator.replace(original, replacement, 1)
                self.assertNotEqual(readonly_submodule_validator_errors(mutated), [])

        namespace_runner_removed = validator.replace(
            "run-readonly-submodule-validation-namespace.py",
            "run-readonly-submodule-validation-namespace.removed.py",
            1,
        )
        self.assertNotEqual(readonly_submodule_validator_errors(namespace_runner_removed), [])

        validate_only_mutations = {
            "automatic schedule is reintroduced": (
                "on:\n  workflow_dispatch:",
                "on:\n  schedule:\n    - cron: '0 3 * * 1'\n  workflow_dispatch:",
            ),
            "input enables validate_only by default": (
                SUBMODULE_VALIDATE_ONLY_INPUT,
                SUBMODULE_VALIDATE_ONLY_INPUT.replace("default: false", "default: true"),
            ),
            "fork gate removed from resolver": (
                "github.event.repository.fork == false &&",
                "github.event.repository.fork == true ||",
            ),
            "canonical repository constraint removed": (
                SUBMODULE_VALIDATE_ONLY_REPOSITORY,
                "true",
            ),
            "canonical repository constraint changed": (
                SUBMODULE_VALIDATE_ONLY_REPOSITORY,
                "github.repository == 'attacker/ModSecurity-conector'",
            ),
            "repair branch constraint removed": (
                SUBMODULE_VALIDATE_ONLY_BRANCH,
                "true",
            ),
            "repair branch constraint changed": (
                SUBMODULE_VALIDATE_ONLY_BRANCH,
                "github.ref == 'refs/heads/arbitrary-validator-branch'",
            ),
            "protected master removed from validate_only allowlist": (
                SUBMODULE_VALIDATE_ONLY_PROTECTED_MASTER,
                "false",
            ),
            "protected master loses default-branch condition": (
                SUBMODULE_VALIDATE_ONLY_PROTECTED_MASTER,
                "(github.ref == 'refs/heads/master')",
            ),
            "protected-ref condition deleted": (
                SUBMODULE_VALIDATE_ONLY_PROTECTED_FLAG,
                "true",
            ),
            "protected-ref condition inverted": (
                SUBMODULE_VALIDATE_ONLY_PROTECTED_FLAG,
                "github.ref_protected != true",
            ),
            "unprotected master explicitly allowed": (
                SUBMODULE_VALIDATE_ONLY_PROTECTED_FLAG,
                "github.ref_protected == false",
            ),
            "master clause admits validate_only dispatch": (
                SUBMODULE_VALIDATE_ONLY_MASTER_EXCLUSION,
                "true",
            ),
            "scheduled run admitted through manual test gate": (
                SUBMODULE_VALIDATE_ONLY_EVENT,
                "github.event_name == 'schedule' && "
                "github.event.inputs.validate_only == 'true'",
            ),
            "resolver validates default branch instead of dispatched SHA": (
                SUBMODULE_VALIDATE_ONLY_CHECKOUT_REF,
                "ref: ${{ github.event.repository.default_branch }}",
            ),
            "resolver activation omits hosted-proof constraints": (
                f'if [ "${{{{ {SUBMODULE_VALIDATE_ONLY_MANUAL_PREDICATE} }}}}" = true ]; then',
                f'if [ "${{{{ {SUBMODULE_VALIDATE_ONLY_EVENT} }}}}" = true ]; then',
            ),
            "validate_only does not force existing gitlink validation": (
                'if [ "$validation_only" = true ]; then\n'
                "            changed=true\n"
                "          fi",
                'if [ "$validation_only" = true ]; then\n'
                "            changed=false\n"
                "          fi",
            ),
            "later resolver assignment cancels validate_only forcing": (
                "          {\n            printf 'candidate_sha=%s\\n'",
                "          changed=false\n          {\n            printf 'candidate_sha=%s\\n'",
            ),
            "publisher admits validate_only": (
                "needs.resolve-submodule-update.outputs.validation_only == 'false' &&",
                "needs.resolve-submodule-update.outputs.validation_only != 'true' &&",
            ),
            "resolver gains write permission": (
                "    permissions:\n      contents: read",
                "    permissions:\n      contents: write",
            ),
            "resolver receives publisher credential": (
                "    runs-on: ubuntu-26.04",
                "    env:\n      GH_TOKEN: ${{ github.token }}\n    runs-on: ubuntu-26.04",
            ),
            "publisher enables auto-merge": (
                "--draft",
                "--draft --auto",
            ),
            "outcome ignores resolver validation_only output": (
                "VALIDATION_ONLY: ${{ needs.resolve-submodule-update.outputs.validation_only }}",
                "VALIDATION_ONLY: ${{ needs.resolve-submodule-update.outputs.changed }}",
            ),
            "validate_only outcome requires publisher success": (
                'if [ "$CHANGED" != "true" ] || [ "$VALIDATOR_RESULT" != "success" ] || [ "$PUBLISHER_RESULT" != "skipped" ]; then',
                'if [ "$CHANGED" != "true" ] || [ "$VALIDATOR_RESULT" != "success" ] || [ "$PUBLISHER_RESULT" != "success" ]; then',
            ),
            "validate_only outcome falls through to publishing checks": (
                "              exit 0\n              ;;\n            false)",
                "              ;;\n            false)",
            ),
            "normal update accepts skipped publisher": (
                'if [ "$VALIDATOR_RESULT" != "success" ] || [ "$PUBLISHER_RESULT" != "success" ]; then',
                'if [ "$VALIDATOR_RESULT" != "success" ] || [ "$PUBLISHER_RESULT" != "skipped" ]; then',
            ),
        }
        for name, (original, replacement) in validate_only_mutations.items():
            with self.subTest(validate_only_mutation=name):
                self.assertIn(original, workflow)
                mutated = workflow.replace(original, replacement, 1)
                self.assertNotEqual(update_submodule_validate_only_errors(mutated), [])

        publisher_token_mutations = {
            "publisher falls back to ambient token": (
                SUBMODULE_PUBLISHER_APP_TOKEN_OUTPUT,
                "${{ github.token }}",
            ),
            "publisher App token gains unrelated issue scope": (
                "          permission-workflows: write\n",
                "          permission-workflows: write\n          permission-issues: write\n",
            ),
            "publisher receives an unrelated secret": (
                "          permission-workflows: write\n",
                "          permission-workflows: write\n        env:\n"
                "          UNRELATED_SECRET: ${{ secrets.UNRELATED }}\n",
            ),
            "publisher receives a bracket-indexed secret": (
                "          permission-workflows: write\n",
                "          permission-workflows: write\n        env:\n"
                "          UNRELATED_SECRET: ${{ secrets['UNRELATED'] }}\n",
            ),
            "publisher App token targets another repository": (
                "          repositories: ${{ github.repository }}\n",
                "          repositories: another-owner/another-repository\n",
            ),
        }
        for name, (original, replacement) in publisher_token_mutations.items():
            with self.subTest(publisher_token_mutation=name):
                self.assertIn(original, workflow)
                mutated = workflow.replace(original, replacement, 1)
                self.assertNotEqual(submodule_publisher_token_errors(mutated), [])

        publisher_with_ambient_write = publisher.replace(
            "    permissions:\n      contents: read",
            "    permissions:\n      contents: write\n      pull-requests: write",
            1,
        )
        mutated = workflow.replace(publisher, publisher_with_ambient_write, 1)
        self.assertNotEqual(submodule_publisher_token_errors(mutated), [])

        self.assertIn("submodules: false", publisher)
        self.assertEqual(
            sha256(normalize_locked_action_pins(publisher).encode("utf-8")).hexdigest(),
            SUBMODULE_PUBLISHER_NORMALIZED_SHA256,
        )
        self.assertIn("persist-credentials: false", publisher)
        self.assertIn("id: setup-python", publisher)
        self.assertIn(
            "EXPECTED_PYTHON: ${{ steps.setup-python.outputs.python-path }}",
            publisher,
        )
        self.assertIn(
            "python3 ci/checks/common/check-python-interpreter-contract.py "
            "--version-file .python-version --expected-python \"$EXPECTED_PYTHON\"",
            publisher,
        )
        self.assertIn("grep -Fqx", publisher)
        self.assertIn('-e "$SUBMODULE_PATH"', publisher)
        self.assertNotIn('case "$changed_path" in', publisher)
        self.assertEqual(
            job_if_expression(publisher),
            SUBMODULE_PUBLISHER_GATE,
        )
        self.assertNotIn(SUBMODULE_VALIDATE_ONLY_CHECKOUT_REF, publisher)
        self.assertNotIn("gh pr merge", publisher)
        self.assertNotIn("--auto", publisher)
        self.assertNotIn("enablePullRequestAutoMerge", publisher)
        self.assertIn("git ls-remote --exit-code", publisher)
        self.assertTrue(has_exact_framework_gitlink_staging(publisher))
        self.assertIn(f"GH_TOKEN: {SUBMODULE_PUBLISHER_APP_TOKEN_OUTPUT}", publisher)
        self.assertNotIn("${{ github.token }}", publisher)
        self.assertIn("git read-tree \"$MASTER_HEAD\"", publisher)
        self.assertIn('git diff --cached --name-only "$MASTER_HEAD"', normalized_publisher)
        self.assertIn("require_only_allowed_update_paths", publisher)
        self.assertIn("require_expected_update_raw", publisher)
        self.assertIn("git diff --cached --raw --no-abbrev --no-renames", normalized_publisher)
        self.assertIn("CANDIDATE_SHA", publisher)
        self.assertIn("CURRENT_GITLINK_SHA", publisher)
        self.assertIn("MASTER_OLD_SHA", publisher)
        self.assertIn("Parent master Framework gitlink changed after resolution", publisher)
        self.assertIn("PR_MARKER", publisher)
        self.assertIn("--draft", publisher)
        self.assertIn(".auto_merge", publisher)
        self.assertIn(
            "pr_auto_merge=\"$(gh api --method GET "
            "\"repos/$GITHUB_REPOSITORY/pulls/$pr_number\" "
            "--jq 'if (has(\"auto_merge\") and (.auto_merge == null)) then \"null\" "
            "else \"auto-merge-present\" end')\"",
            publisher,
        )
        self.assertIn(AUTO_MERGE_DISABLED_QUERY, publisher)
        self.assertNotIn(".auto_merge //", publisher)
        self.assertIn('has("auto_merge")', publisher)
        self.assertIn('else "auto-merge-present" end', publisher)
        for state_name, payload, expected in (
            ("present JSON null", {"auto_merge": None}, "null"),
            ("boolean false", {"auto_merge": False}, "auto-merge-present"),
            ("string null", {"auto_merge": "null"}, "auto-merge-present"),
            ("enabled object", {"auto_merge": {}}, "auto-merge-present"),
            ("missing field", {}, "auto-merge-present"),
        ):
            with self.subTest(auto_merge_state=state_name):
                normalized = (
                    "null"
                    if "auto_merge" in payload and payload["auto_merge"] is None
                    else "auto-merge-present"
                )
                self.assertEqual(normalized, expected)
        self.assertIn('[ "$pr_auto_merge" = "null" ] && auto_merge_present=false', publisher)
        self.assertIn("marker_count", publisher)
        self.assertIn("verify_open_pr_identity", publisher)
        self.assertIn("verify_open_draft_pr", publisher)
        self.assertIn("ensure_open_pr_is_draft", publisher)
        self.assertIn('gh pr ready "$pr_number" --repo "$GITHUB_REPOSITORY" --undo', publisher)
        self.assertLess(
            publisher.index('verify_open_pr_identity "$pr_number" "$expected_head"'),
            publisher.index('gh pr ready "$pr_number" --repo "$GITHUB_REPOSITORY" --undo'),
        )
        self.assertIn('[ "$pr_draft" != "true" ]', publisher)
        self.assertIn('[ "$pr_base_repo" != "$GITHUB_REPOSITORY" ]', publisher)
        self.assertIn('[ "$pr_head_repo" != "$GITHUB_REPOSITORY" ]', publisher)
        self.assertIn("verify_merged_pr", publisher)
        merged_guard = re.search(r"(?ms)^          verify_merged_pr\(\) \{\n.*?^          \}", publisher)
        self.assertIsNotNone(merged_guard)
        assert merged_guard is not None
        for required_check in (
            '[ "$pr_base_repo" != "$GITHUB_REPOSITORY" ]',
            '[ "$pr_head_repo" != "$GITHUB_REPOSITORY" ]',
            '[ "$marker_count" != "1" ]',
            "--jq '.merge_commit_sha'",
            'git cat-file -e "$pr_merge_sha^{commit}"',
            'git merge-base --is-ancestor "$pr_merge_sha" "origin/$DEFAULT_BRANCH"',
        ):
            self.assertIn(required_check, merged_guard.group(0))
        merged_state = re.search(r"(?ms)^            0:true\)\n(.*?)^              ;;", publisher)
        self.assertIsNotNone(merged_state)
        assert merged_state is not None
        self.assertNotIn("require_single_updater_commit", merged_state.group(1))
        self.assertIn('verify_merged_pr "$MERGED_PR_NUMBER" "$EXPECTED_REMOTE_HEAD"', merged_state.group(1))
        self.assertIn("require_single_updater_commit", publisher)
        self.assertIn("git rev-list --reverse", publisher)
        self.assertIn("read_matching_merged_pr", publisher)
        self.assertIn('case "$OPEN_PR_COUNT:$UPDATE_BRANCH_PRESENT" in', publisher)
        self.assertIn("BRANCH_STATE=A", publisher)
        self.assertIn("BRANCH_STATE=B", publisher)
        self.assertIn("BRANCH_STATE=C", publisher)
        self.assertIn("Unsafe maintenance branch/pull-request state", publisher)
        self.assertIn("Maintenance state changed before normal branch creation", publisher)
        self.assertIn("Maintenance branch or pull request changed before lease-bound update", publisher)
        self.assertIn("Maintenance branch or pull request changed before lease-bound reuse", publisher)
        self.assertIn(
            'git push --force-with-lease="refs/heads/$UPDATE_BRANCH:$EXPECTED_REMOTE_HEAD" origin "$NEW_COMMIT:refs/heads/$UPDATE_BRANCH"',
            publisher,
        )
        self.assertIn('git push origin "$NEW_COMMIT:refs/heads/$UPDATE_BRANCH"', publisher)
        self.assertNotIn("git checkout -B", publisher)
        self.assertNotIn("git push --force origin", publisher)
        self.assertNotIn("git push --force-with-lease origin", publisher)
        self.assertIn("sync-framework-component-versions.py", publisher)
        self.assertIn("--sync", publisher)
        self.assertIn("--check", publisher)
        self.assertEqual(publisher.count('--framework-sha "$CANDIDATE_SHA"'), 4)
        self.assertEqual(publisher.count("--verify-companions"), 2)
        self.assertEqual(publisher.count('--base "$MASTER_HEAD"'), 2)
        self.assertEqual(publisher.count("--staged"), 1)
        for companion in ("config/testing/active-cases.json",
                          "reports/testing/test-selection-archive.generated.json"):
            self.assertEqual(publisher.count(companion), 3)
        first_proof = publisher.index("--verify-companions")
        staged_proof = publisher.rindex("--verify-companions")
        staging = publisher.index('git -c core.hooksPath=/dev/null add --')
        self.assertLess(publisher.index("python3 scripts/generate_compiler_guides.py"), first_proof)
        self.assertLess(first_proof, staging)
        self.assertLess(staging, staged_proof)
        self.assertLess(staged_proof, publisher.index('git write-tree'))
        self.assertIn("verify-framework-candidate-contract.py", publisher)
        self.assertIn('--candidate-sha "$CANDIDATE_SHA"', publisher)
        self.assertEqual(
            publisher.count('--expected-parent-framework-sha "$MASTER_OLD_SHA"'), 1
        )
        self.assertEqual(
            publisher.count('--expected-parent-framework-sha "$CANDIDATE_SHA"'), 1
        )
        self.assertLess(
            publisher.index('--expected-parent-framework-sha "$MASTER_OLD_SHA"'),
            publisher.index("python3 ci/tools/sync-framework-component-versions.py"),
        )
        self.assertLess(
            publisher.index("--sync"),
            publisher.index('--expected-parent-framework-sha "$CANDIDATE_SHA"'),
        )
        self.assertEqual(publisher.count("ci/tooling/project-versions.lock.json"), 3)
        self.assertNotIn(".github/workflows/test-connectors-with-crs-no-mrts.yml", publisher)
        self.assertNotIn("tests/test_ci_security_workflows.py", publisher)
        candidate_root = '--candidate-framework-root "$GITHUB_WORKSPACE/$SUBMODULE_PATH"'
        self.assertEqual(publisher.count(candidate_root), 2)
        self.assertEqual(validator.count(candidate_root), 1)
        self.assertIn("python3 scripts/generate_compiler_guides.py", publisher)
        self.assertGreaterEqual(publisher.count("scripts/generate_compiler_guides.py"), 3)
        self.assertGreaterEqual(publisher.count("tests/test_compiler_guides.py"), 3)
        self.assertEqual(publisher.count("tests/test_prepare_runtime_components.py"), 3)
        self.assertIn("docs/build/compilers/lighttpd.de.md", publisher)
        self.assertIn('git -c core.hooksPath=/dev/null add --', publisher)
        self.assertNotIn("git add .", publisher)
        self.assertNotIn("git add -A", publisher)
        self.assertNotIn("|| true", publisher)
        self.assertNotIn("continue-on-error", publisher)
        self.assertNotIn("GH_PAT", publisher)
        self.assertNotIn("PERSONAL_ACCESS_TOKEN", publisher)
        self.assertNotIn("DEPLOY_KEY", publisher)
        self.assertNotIn("submodules: recursive", publisher)
        self.assertIn(
            'git -c protocol.file.allow=never submodule update --init -- "$SUBMODULE_PATH"',
            publisher,
        )
        self.assertNotIn("submodule update --init --recursive", publisher)
        self.assertNotIn("make quick-check", publisher)
        self.assertTrue((source_path('ci/tools/verify-framework-candidate-contract.py', root=ROOT)).is_file())

        self.assertIn("RESOLVER_RESULT", outcome)
        self.assertIn("VALIDATOR_RESULT", outcome)
        self.assertIn("PUBLISHER_RESULT", outcome)
        self.assertIn("RESOLVER_STATUS", outcome)
        self.assertIn('case "$CHANGED" in', outcome)
        self.assertIn('false)', outcome)
        self.assertIn('"$VALIDATOR_RESULT" != "skipped"', outcome)
        self.assertIn('"$PUBLISHER_RESULT" != "skipped"', outcome)
        self.assertIn('true)', outcome)
        self.assertIn('"$VALIDATOR_RESULT" != "success"', outcome)
        self.assertIn('"$PUBLISHER_RESULT" != "success"', outcome)
        self.assertIn("Submodule resolver output is missing or malformed", outcome)
        self.assertIn("Submodule resolver changed output is missing or unexpected", outcome)
        self.assertIn(
            "The Framework submodule already points to the reviewed current master commit. No branch, commit, or pull request was created or modified.",
            outcome,
        )
        self.assertIn(
            "Das Framework-Submodule zeigt bereits auf den geprüften aktuellen Master-Commit. Es wurde kein Branch, Commit oder Pull Request erstellt oder verändert.",
            outcome,
        )
        self.assertNotIn("GH_TOKEN", outcome)
        self.assertNotIn("secrets.", outcome)
        self.assertNotIn("continue-on-error", outcome)

    def test_framework_publisher_companion_raw_modes_are_fail_closed(self) -> None:
        payload = yaml.safe_load(self.workflow("update-submodules.yml"))
        steps = payload["jobs"]["create-submodule-update-pr"]["steps"]
        script = next(step["run"] for step in steps
                      if "require_only_allowed_update_paths() {" in step.get("run", ""))
        guards = []
        for name in ("require_only_allowed_update_paths", "require_expected_update_raw"):
            match = re.search(r"(?ms)^" + name + r"\(\) \{\n.*?^\}", script)
            self.assertIsNotNone(match)
            guards.append(match.group(0))
        command = ("set -euo pipefail\n" + "\n".join(guards)
                   + '\nrequire_only_allowed_update_paths "$CHANGED_PATHS"'
                   + '\nrequire_expected_update_raw "$RAW_DIFF"\n')
        framework = "modules/ModSecurity-test-Framework"
        companions = ("config/testing/active-cases.json",
                      "reports/testing/test-selection-archive.generated.json")
        gitlink = f':160000 160000 {"a" * 40} {"b" * 40} M\t{framework}'

        def admitted(rows: list[tuple[str, str, str, str]]) -> bool:
            raw = [gitlink] + [f':{old} {new} {"c" * 40} {"d" * 40} {status}\t{path}'
                               for old, new, status, path in rows]
            result = subprocess.run(
                ["bash", "-c", command], text=True, capture_output=True, timeout=10,
                env={**os.environ, "SUBMODULE_PATH": framework,
                     "CHANGED_PATHS": "\n".join([framework] + [row[3] for row in rows]),
                     "RAW_DIFF": "\n".join(raw)},
            )
            return result.returncode == 0

        self.assertTrue(admitted([]))
        self.assertTrue(admitted([("100644", "100644", "M", path) for path in companions]))
        for path in companions:
            for old, new, status in (("100644", "100755", "M"), ("100755", "100644", "M"),
                                     ("100644", "120000", "M"), ("000000", "100644", "A"),
                                     ("100644", "000000", "D")):
                with self.subTest(path=path, old=old, new=new, status=status):
                    self.assertFalse(admitted([(old, new, status, path)]))
        self.assertFalse(admitted([("100644", "100644", "M", "config/testing/other.json")]))

    def test_framework_gitlink_staging_contract_normalizes_layout_only(self) -> None:
        one_line = (
            'git update-index --add --cacheinfo '
            '"160000,$CANDIDATE_SHA,$SUBMODULE_PATH"'
        )
        continued = (
            "git update-index \\\n"
            "  --add \\\n"
            '  --cacheinfo "160000,$CANDIDATE_SHA,$SUBMODULE_PATH"'
        )
        self.assertTrue(has_exact_framework_gitlink_staging(one_line))
        self.assertTrue(has_exact_framework_gitlink_staging(continued))
        self.assertFalse(
            has_exact_framework_gitlink_staging(
                'git update-index --cacheinfo "160000,$CANDIDATE_SHA,$SUBMODULE_PATH"'
            )
        )
        self.assertFalse(
            has_exact_framework_gitlink_staging(
                'git update-index --add "160000,$CANDIDATE_SHA,$SUBMODULE_PATH"'
            )
        )
        self.assertFalse(
            has_exact_framework_gitlink_staging(
                'git update-index --add --cacheinfo "100644,$CANDIDATE_SHA,$SUBMODULE_PATH"'
            )
        )
        self.assertFalse(
            has_exact_framework_gitlink_staging(
                'git update-index --add --cacheinfo "160000,$CANDIDATE_SHA,$OTHER_PATH"'
            )
        )
        for broad_staging in ("git add .", "git add -A"):
            self.assertFalse(has_exact_framework_gitlink_staging(f"{one_line}\n{broad_staging}"))

    def test_framework_gitlink_raw_diff_contract_is_functional(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)

            def git(*arguments: str, input_text: str | None = None) -> str:
                return subprocess.run(
                    ["git", *arguments],
                    cwd=repository,
                    input=input_text,
                    text=True,
                    check=True,
                    capture_output=True,
                    env={
                        **os.environ,
                        "GIT_AUTHOR_NAME": "test",
                        "GIT_AUTHOR_EMAIL": "test@example.invalid",
                        "GIT_COMMITTER_NAME": "test",
                        "GIT_COMMITTER_EMAIL": "test@example.invalid",
                    },
                ).stdout.strip()

            git("init", "-q")
            empty_tree = git("mktree", input_text="")
            old_gitlink = git("commit-tree", empty_tree, "-m", "old target")
            new_gitlink = git("commit-tree", empty_tree, "-m", "new target")
            self.assertRegex(old_gitlink, r"^[0-9a-f]{40}$")
            self.assertRegex(new_gitlink, r"^[0-9a-f]{40}$")

            framework_path = "modules/ModSecurity-test-Framework"
            git("update-index", "--add", "--cacheinfo", f"160000,{old_gitlink},{framework_path}")
            parent_tree = git("write-tree")
            parent_commit = git("commit-tree", parent_tree, "-m", "parent")
            git("read-tree", parent_commit)
            git("update-index", "--add", "--cacheinfo", f"160000,{new_gitlink},{framework_path}")
            index_entry = git("ls-files", "--stage", "--", framework_path).split()
            self.assertEqual(index_entry[:2], ["160000", new_gitlink])

            raw = git("diff", "--cached", "--raw", "--no-abbrev", "--no-renames", parent_commit)
            records = raw.splitlines()
            expected = re.compile(
                rf"^:160000 160000 {old_gitlink} {new_gitlink} M\t{re.escape(framework_path)}$"
            )
            self.assertEqual(len(records), 1)
            self.assertRegex(records[0], expected)

            extra_blob = git("hash-object", "-w", "--stdin", input_text="extra\n")
            git("update-index", "--add", "--cacheinfo", f"100644,{extra_blob},extra.txt")
            widened_records = git(
                "diff", "--cached", "--raw", "--no-abbrev", "--no-renames", parent_commit
            ).splitlines()
            self.assertEqual(len(widened_records), 2)
            self.assertFalse(len(widened_records) == 1 and bool(expected.fullmatch(widened_records[0])))

    def test_workflow_tool_updater_is_the_sole_parent_only_action_maintainer(self) -> None:
        for retired_path in (
            WORKFLOWS / "check-actions-versions.yml",
            WORKFLOWS / "update-actions-versions.yml",
            source_path('scripts/check-github-actions-versions.py', root=ROOT),
            source_path('scripts/update-github-actions-versions.py', root=ROOT),
            source_path('tests/test_update_github_actions_versions.py', root=ROOT),
        ):
            self.assertFalse(retired_path.exists(), retired_path)

        common_scaffold = (WORKFLOWS / "test-common.yml").read_text(encoding="utf-8")
        self.assertNotIn("test_update_github_actions_versions.py", common_scaffold)

        dependabot = (source_path('.github/dependabot.yml', root=ROOT)).read_text(encoding="utf-8")
        self.assertNotIn('package-ecosystem: "github-actions"', dependabot)
        self.assertIn('package-ecosystem: "pip"', dependabot)
        configuration = yaml.safe_load(dependabot)
        self.assertEqual(configuration["version"], 2)
        self.assertCountEqual(
            [entry["package-ecosystem"] for entry in configuration["updates"]],
            ["pip", "gomod"],
        )
        pip = next(entry for entry in configuration["updates"]
                   if entry["package-ecosystem"] == "pip")
        self.assertEqual(pip, {
            "package-ecosystem": "pip", "directory": "/",
            "schedule": {"interval": "weekly"},
            "cooldown": {"default-days": 7}, "open-pull-requests-limit": 5,
        })
        parent_manifests = list(ROOT.glob("go.mod"))
        for directory in ROOT.iterdir():
            if directory.is_dir() and directory.name not in {"modules", ".git", ".codex", ".venv"}:
                parent_manifests.extend(directory.rglob("go.mod"))
        module_directories = {
            "/" + manifest.parent.relative_to(ROOT).as_posix() if manifest.parent != ROOT else "/"
            for manifest in parent_manifests if manifest.is_file()
        }
        self.assertTrue(module_directories)
        gomod = next(entry for entry in configuration["updates"]
                     if entry["package-ecosystem"] == "gomod")

        def assert_go_update_scope(candidate):
            self.assertEqual(set(candidate["directories"]), module_directories)
            self.assertEqual(len(candidate["directories"]), len(module_directories))
            self.assertEqual(candidate["schedule"], {"interval": "weekly"})
            self.assertEqual(candidate["cooldown"], {"default-days": 7})
            self.assertEqual(candidate["open-pull-requests-limit"], 5)
            self.assertNotIn("directory", candidate)
            self.assertNotIn("target-branch", candidate)
            self.assertNotIn("ignore", candidate)

        assert_go_update_scope(gomod)
        for module_directory in sorted(module_directories):
            with self.subTest(go_module=module_directory):
                self.assertIn(module_directory, gomod["directories"])
        invalid_scopes = (
            dict(gomod, directories=gomod["directories"][:-1]),
            dict(gomod, directories=[*gomod["directories"], "/modules/ModSecurity-test-Framework"]),
        )
        for candidate in invalid_scopes:
            with self.subTest(invalid_directories=candidate["directories"]):
                with self.assertRaises(AssertionError):
                    assert_go_update_scope(candidate)

        workflow_name = "update-workflow-tools.yml"
        workflow = self.workflow(workflow_name)
        jobs = self.jobs(workflow_name)
        self.assertEqual(set(jobs), {"resolver", "validator", "publisher", "outcome"})
        publisher = jobs["publisher"]
        for required_guard in (
            "github.repository == 'Easton97-Jens/ModSecurity-conector'",
            "github.event.repository.fork == false",
            "github.event.repository.default_branch == 'master'",
            "github.ref == 'refs/heads/master'",
        ):
            self.assertIn(required_guard, publisher)
        for job_name in ("resolver", "validator", "publisher"):
            for checkout in checkout_step_blocks(jobs[job_name]):
                self.assertIn("submodules: false", checkout, job_name)
                self.assertNotIn("submodules: recursive", checkout, job_name)
        for forbidden in (
            "SUBMODULE_UPDATE_TOKEN",
            "modules/ModSecurity-test-Framework",
            "git submodule",
            "module_repo",
            "automation/update-github-actions-versions",
        ):
            self.assertNotIn(forbidden, workflow)

    def test_parent_updaters_use_ephemeral_askpass_for_publisher_app_tokens(self) -> None:
        """Keep the publisher token out of Git config and scope askpass to trusted network Git."""

        publisher_jobs = {
            "update-workflow-tools.yml": "publisher",
            "update-python-version.yml": "publish-python-update",
        }
        setup_terms = (
            'askpass_script="$(mktemp "$RUNNER_TEMP/modsecurity-conector-publisher-askpass.XXXXXX")"',
            "https://x-access-token@github.com'",
            'https://x-access-token@github.com/"',
            'PUBLISH_REMOTE_URL="https://github.com/Easton97-Jens/ModSecurity-conector.git"',
            'origin_url="$(git remote get-url origin)"',
            'https://github.com/Easton97-Jens/ModSecurity-conector|https://github.com/Easton97-Jens/ModSecurity-conector.git)',
            'echo "::error::unexpected publisher origin" >&2',
            'GIT_ASKPASS="$askpass_script" GIT_TERMINAL_PROMPT=0',
            "git -c credential.helper=",
            "-c credential.https://github.com.username=x-access-token",
            '-c credential.https://github.com.useHttpPath=false "$@"',
            "trap cleanup_publisher_askpass EXIT",
            'rm -f -- "$askpass_script"',
            'printf \'%s\\n\' "$PUBLISH_TOKEN"',
        )
        for workflow_name, publisher_name in publisher_jobs.items():
            jobs = self.jobs(workflow_name)
            publisher = jobs[publisher_name]
            self.assertNotIn("git config --local credential.", publisher, workflow_name)
            self.assertNotIn("export GIT_ASKPASS", publisher, workflow_name)
            self.assertNotIn("export GIT_TERMINAL_PROMPT", publisher, workflow_name)
            self.assertNotIn("password", publisher.lower(), workflow_name)
            for setup_term in setup_terms:
                self.assertEqual(
                    publisher.count(setup_term),
                    2,
                    (workflow_name, setup_term),
                )
            self.assertEqual(
                publisher.count('publisher_git fetch --no-tags "$PUBLISH_REMOTE_URL"'),
                2,
                workflow_name,
            )
            self.assertNotIn(
                "publisher_git fetch --no-tags origin",
                publisher,
                workflow_name,
            )
            self.assertEqual(publisher.count("publisher_git push"), 2, workflow_name)
            self.assertEqual(
                publisher.count(
                    '"$PUBLISH_REMOTE_URL" "HEAD:refs/heads/$UPDATE_BRANCH"'
                ),
                2,
                workflow_name,
            )
            self.assertNotIn("publisher_git push origin", publisher, workflow_name)
            self.assertEqual(
                publisher.count(
                    "PUBLISH_TOKEN: ${{ steps.publisher_app_token.outputs.token }}"
                ),
                2,
                workflow_name,
            )
            for checkout in checkout_step_blocks(publisher):
                self.assertIn("persist-credentials: false", checkout, workflow_name)
            for job_name, job in jobs.items():
                if job_name != publisher_name:
                    self.assertNotIn("PUBLISH_TOKEN:", job, (workflow_name, job_name))

    def test_python_patch_updater_separates_trusted_stages_and_writer_scope(self) -> None:
        workflow_name = "update-python-version.yml"
        workflow = self.workflow(workflow_name)
        jobs = self.jobs(workflow_name)
        self.assertEqual(
            set(jobs),
            {
                "resolve-python-patch",
                "validate-python-patch",
                "publish-python-update",
                "report-python-update-outcome",
            },
        )
        self.assertEqual(top_level_permissions(workflow), {})
        self.assertIn(
            "group: modsecurity-conector-python-version-maintenance-${{ github.repository }}",
            workflow,
        )
        self.assertIn("cancel-in-progress: false", workflow)
        for disallowed_trigger in (
            "push:",
            "pull_request:",
            "pull_request_target:",
            "workflow_run:",
            "repository_dispatch:",
        ):
            self.assertNotIn(f"  {disallowed_trigger}", workflow)
        self.assertIn("- cron: '17 6 * * 1'", workflow)
        self.assertIn("  workflow_dispatch:", workflow)

        canonical_gate_terms = {
            "github.repository == 'Easton97-Jens/ModSecurity-conector'",
            "github.event.repository.fork == false",
            "github.event.repository.default_branch == 'master'",
            "github.ref == 'refs/heads/master'",
            "github.event_name == 'schedule'",
            "github.event_name == 'workflow_dispatch'",
        }
        for job_name in (
            "resolve-python-patch",
            "validate-python-patch",
            "publish-python-update",
        ):
            expression = job_if_expression(jobs[job_name])
            self.assertIsNotNone(expression, job_name)
            for term in canonical_gate_terms:
                self.assertIn(term, expression, job_name)
            checkouts = checkout_step_blocks(jobs[job_name])
            self.assertEqual(len(checkouts), 1, job_name)
            self.assertIn("ref: ${{ github.sha }}", checkouts[0], job_name)
            self.assertIn("fetch-depth: 1", checkouts[0], job_name)
            self.assertIn("submodules: false", checkouts[0], job_name)
            self.assertIn("persist-credentials: false", checkouts[0], job_name)

        self.assertNotIn("secrets.", jobs["resolve-python-patch"])
        self.assertNotIn("secrets.", jobs["validate-python-patch"])
        candidate_install = 'python3 ci/tools/install-ci-dependencies.py --ci-toolcache --expected-version "$CANDIDATE_VERSION"'
        self.assertIn(candidate_install, normalize_shell_script(jobs["validate-python-patch"]))
        self.assertEqual(workflow.count(candidate_install), 1)

        self.assertEqual(job_permissions(jobs["resolve-python-patch"]), {"contents": "read"})
        self.assertEqual(job_permissions(jobs["validate-python-patch"]), {"contents": "read"})
        publisher = jobs["publish-python-update"]
        self.assertEqual(job_permissions(publisher), {"contents": "read"})
        self.assertIn("needs.resolve-python-patch.outputs.update_available == 'true'", publisher)
        self.assertIn("needs.validate-python-patch.result == 'success'", publisher)
        self.assertIn("WORKFLOW_UPDATER_APP_CLIENT_ID", publisher)
        self.assertIn("WORKFLOW_UPDATER_APP_PRIVATE_KEY", publisher)
        self.assertIn("::error::WORKFLOW_UPDATER_APP_CLIENT_ID", publisher)
        self.assertIn("::error::WORKFLOW_UPDATER_APP_PRIVATE_KEY", publisher)
        self.assertIn(locked_action_pin("actions/create-github-app-token"), publisher)
        self.assertIn("permission-contents: write", publisher)
        self.assertIn("permission-pull-requests: write", publisher)
        self.assertNotIn("permission-workflows:", publisher)
        self.assertNotIn("permission-actions:", publisher)
        self.assertNotIn("permission-issues:", publisher)
        self.assertNotIn("github.token", publisher)
        self.assertNotIn("GH_TOKEN:", publisher)
        for job_name, job in jobs.items():
            if job_name != "publish-python-update":
                self.assertNotIn("WORKFLOW_UPDATER_APP_CLIENT_ID", job, job_name)
                self.assertNotIn("WORKFLOW_UPDATER_APP_PRIVATE_KEY", job, job_name)

        self.assertNotIn("submodules: recursive", publisher)
        self.assertNotIn("git submodule", publisher)
        self.assertNotIn("gh ", publisher)
        self.assertNotIn("scripts/select-python-update-pr.py", publisher)
        self.assertNotIn("grep -Eq", publisher)
        self.assertNotIn("re.compile", publisher)
        publisher_normalized = normalize_shell_script(publisher)
        publisher_install_step = "Install hash-locked CI test dependency"
        publisher_install_command = (
            "python3 ci/tools/install-ci-dependencies.py --ci-toolcache"
        )
        self.assertIn(publisher_install_step, publisher)
        self.assertIn(publisher_install_command, publisher_normalized)
        self.assertIn("python3 -m pip check", publisher_normalized)
        self.assertLess(
            publisher.index("Verify Python interpreter contract"),
            publisher.index(publisher_install_step),
        )
        self.assertLess(
            publisher.index(publisher_install_step),
            publisher.index("Mint repository-limited Python updater App token"),
        )
        self.assertLess(
            publisher.index(publisher_install_step),
            publisher.index("Revalidate current master before modifying it"),
        )
        self.assertLess(
            publisher_normalized.index(publisher_install_command),
            publisher_normalized.index("python3 -m pip check"),
        )
        self.assertLess(
            publisher_normalized.index("python3 -m pip check"),
            publisher_normalized.index("make check-ci-security-contract"),
        )
        self.assertIn(
            'python3 scripts/update-python-version.py --check --expected-version "$CANDIDATE_VERSION" --json',
            publisher,
        )
        self.assertIn(
            'python3 scripts/update-python-version.py --update --expected-version "$CANDIDATE_VERSION" --json',
            publisher,
        )
        self.assertIn("UPDATE_BRANCH: automation/update-python-315", publisher)
        self.assertIn('PR_TITLE: "chore(ci): propose Python 3.15 patch update"', publisher)
        self.assertIn('PR_MARKER: "<!-- modsecurity-conector-python-315-updater -->"', publisher)
        self.assertIn("FRAMEWORK_REFERENCE_SHA: 3cb33609626ff689c54b6dc0f31fb7e9401fe75e", publisher)
        self.assertIn(
            'PUBLISH_REMOTE_URL="https://github.com/Easton97-Jens/ModSecurity-conector.git"',
            publisher,
        )
        self.assertIn(
            'git fetch --no-tags "$PUBLISH_REMOTE_URL" "refs/heads/$DEFAULT_BRANCH:refs/remotes/origin/$DEFAULT_BRANCH"',
            publisher,
        )
        self.assertNotIn('git fetch --no-tags origin', publisher)
        self.assertIn('git reset --hard "origin/$DEFAULT_BRANCH"', publisher)
        self.assertIn('branch_paths="$(git diff --name-only "$merge_base" "origin/$UPDATE_BRANCH")"', publisher)
        expected_paths = "$(printf '%s\\n' .python-version ci/tooling/project-versions.lock.json)"
        companion_paths = "$(printf '%s\\n' .python-version ci/tooling/project-versions.lock.json config/testing/active-cases.json reports/testing/test-selection-archive.generated.json)"
        self.assertIn(f'if [ "$branch_paths" != "{expected_paths}" ] &&', publisher)
        self.assertIn(f'[ "$branch_paths" != "{companion_paths}" ]; then', publisher)
        self.assertIn('"--force-with-lease=refs/heads/$UPDATE_BRANCH:$EXPECTED_REMOTE_TIP"', publisher)
        self.assertNotRegex(publisher, r"git push\s+--force(?:\s|$)")
        self.assertNotRegex(publisher, r"git push\s+--force-with-lease(?:\s|$)")
        self.assertNotIn('origin "HEAD:refs/heads/master"', publisher)
        self.assertNotIn("pulls.merge", publisher)
        self.assertNotIn("gh pr merge", publisher)
        self.assertIn("github.rest.git.listMatchingRefs", publisher)
        self.assertIn("github.paginate(github.rest.pulls.list", publisher)
        self.assertIn("pullRequest.head.repo?.full_name !== repository", publisher)
        self.assertIn("pullRequest.base.repo?.full_name !== repository", publisher)
        self.assertIn("pullRequest.auto_merge !== null", publisher)
        self.assertIn("draft: true", publisher)
        self.assertIn("Recheck the matching Draft pull request after publication", publisher)
        self.assertIn("pullRequest.head.sha !== process.env.EXPECTED_HEAD_SHA", publisher)
        self.assertIn('changed_paths="$(git diff --name-only "origin/$DEFAULT_BRANCH" --)"', publisher)
        self.assertIn(f'if [ "$changed_paths" != "{expected_paths}" ] &&', publisher)
        self.assertIn(f'[ "$changed_paths" != "{companion_paths}" ]; then', publisher)
        field_check = "python3 ci/tools/sync-project-versions.py --verify-update python"
        self.assertIn(field_check, publisher)
        staging = 'git add -- .python-version ci/tooling/project-versions.lock.json config/testing/active-cases.json reports/testing/test-selection-archive.generated.json'
        self.assertLess(publisher.index(field_check), publisher.index(staging))
        self.assertIn(staging, publisher)
        self.assertIn('staged_paths="$(git diff --cached --name-only)"', publisher)
        self.assertIn(f'if [ "$staged_paths" != "{expected_paths}" ] &&', publisher)
        self.assertIn(f'[ "$staged_paths" != "{companion_paths}" ]; then', publisher)
        companion_check = "python3 ci/lib/active_inventory_updates.py verify --kind python --base HEAD"
        self.assertLess(publisher.index(companion_check), publisher.index(staging))
        self.assertIn(companion_check + " --staged", publisher)
        self.assertIn("(records == 2 || records == 4) && !invalid", publisher)
        self.assertIn("git diff --cached --check", publisher)
        self.assertNotIn("git add -A", publisher)
        self.assertNotIn("git add .", publisher)
        self.assertIn("UPDATE_CHANGED: ${{ steps.update.outputs.changed }}", publisher)
        self.assertIn('if [ "$UPDATE_CHANGED" != true ]; then', publisher)
        self.assertNotIn('if [ "${{ steps.update.outputs.changed }}" != true ]; then', publisher)
        self.assertIn("## English", publisher)
        self.assertIn("## Deutsch", publisher)
        self.assertIn("Automatic merge remains disabled.", publisher)
        self.assertIn("Automatischer Merge bleibt deaktiviert.", publisher)

        resolver = jobs["resolve-python-patch"]
        self.assertIn("status: ${{ steps.resolve.outputs.status }}", resolver)
        self.assertIn("current_version: ${{ steps.resolve.outputs.current_version }}", resolver)
        self.assertIn("latest_version: ${{ steps.resolve.outputs.latest_version }}", resolver)
        self.assertIn("update_available: ${{ steps.resolve.outputs.update_available }}", resolver)
        self.assertIn('scripts/update-python-version.py --check --json', resolver)
        self.assertNotIn("re.compile", resolver)
        self.assertNotIn("grep -Eq", resolver)

        candidate = jobs["validate-python-patch"]
        assert_hash_locked_ci_test_dependency_installation(
            self,
            candidate,
            interpreter_contract_step="Verify Python candidate interpreter contract",
            first_test_step="Run focused Python version contracts",
        )
        self.assertIn("python-version: ${{ needs.resolve-python-patch.outputs.latest_version }}", candidate)
        self.assertIn("check-latest: false", candidate)
        self.assertIn("python3 -m compileall -q ci scripts tests", candidate)
        self.assertIn("make check-ci-security-contract", candidate)
        self.assertIn(
            'check-python-interpreter-contract.py --expected-version "$EXPECTED_VERSION" --expected-python "$EXPECTED_PYTHON"',
            candidate,
        )
        self.assertIn(
            'scripts/update-python-version.py --check --expected-version "$CANDIDATE_VERSION" --json',
            candidate,
        )

        outcome = jobs["report-python-update-outcome"]
        self.assertEqual(job_permissions(outcome), {})
        self.assertEqual(job_if_expression(outcome), "always()")
        self.assertNotIn("secrets.", outcome)
        self.assertNotIn("publisher_app_token", outcome)
        self.assertIn("case \"$UPDATE_AVAILABLE\" in", outcome)
        self.assertIn("No Python 3.15 patch update is available.", outcome)
        self.assertIn("Kein Python-3.15-Patch-Update ist verfügbar.", outcome)

    def test_go_release_updater_separates_trusted_stages_and_writer_scope(self) -> None:
        workflow_name = "update-go-version.yml"
        jobs = self.jobs(workflow_name)
        self.assertEqual(
            set(jobs),
            {
                "resolve-go-release",
                "validate-go-release",
                "create-go-update-pr",
            },
        )
        trusted_default_ref = "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
        for job_name in ("resolve-go-release", "validate-go-release", "create-go-update-pr"):
            self.assertIn(trusted_default_ref, jobs[job_name], job_name)
            checkouts = checkout_step_blocks(jobs[job_name])
            self.assertEqual(len(checkouts), 1, job_name)
            self.assertIn("ref: ${{ github.event.repository.default_branch }}", checkouts[0], job_name)
            self.assertIn("submodules: false", checkouts[0], job_name)
            self.assertIn("persist-credentials: false", checkouts[0], job_name)
            self.assertNotIn("secrets.", jobs[job_name], job_name)

        self.assertEqual(job_permissions(jobs["resolve-go-release"]), {"contents": "read"})
        self.assertEqual(job_permissions(jobs["validate-go-release"]), {"contents": "read"})
        resolver = jobs["resolve-go-release"]
        self.assertIn("go-version-file: .go-version", resolver)
        self.assertIn("check-latest: false", resolver)
        self.assertIn("cache: false", resolver)
        self.assertIn("make check-go-version-contract", resolver)
        self.assertIn('scripts/update-go-version.py --check --json', resolver)
        self.assertIn('scripts/update-go-components.py --check --json', resolver)
        self.assertIn("go_version_tuple", resolver)
        self.assertIn("latest_version", resolver)
        self.assertNotIn("1.26", resolver)
        self.assertIn("component_version_tuple", resolver)
        self.assertIn("component_available != requirement_available", resolver)
        self.assertIn("requirement.get(\"update_available\") is not update", resolver)
        self.assertIn('"golang.org/x/net": "v0.61.0"', resolver)
        self.assertIn('"golang.org/x/sys": "v0.49.0"', resolver)
        self.assertIn('"golang.org/x/text": "v0.43.0"', resolver)
        self.assertIn("toolchain_update_available", resolver)
        self.assertIn("component_update_available", resolver)
        self.assertIn('"connectors/envoy/ext_proc"', resolver)
        self.assertIn('"google.golang.org/grpc"', resolver)
        self.assertIn('"v1.83.2"', resolver)

        candidate = jobs["validate-go-release"]
        assert_hash_locked_ci_test_dependency_installation(
            self,
            candidate,
            interpreter_contract_step="Verify Python interpreter contract",
            first_test_step="Run Go version and workflow contracts",
        )
        self.assertIn("go-version: ${{ needs.resolve-go-release.outputs.latest_version }}", candidate)
        self.assertIn("GOTOOLCHAIN: local", candidate)
        self.assertIn("GOWORK: off", candidate)
        self.assertEqual(candidate.count("go mod tidy -diff"), 4)
        self.assertEqual(candidate.count("go mod verify"), 4)
        self.assertEqual(candidate.count("go test -mod=readonly ./..."), 4)
        self.assertEqual(candidate.count("go test -race -mod=readonly ./..."), 4)
        self.assertEqual(candidate.count("go vet -mod=readonly ./..."), 4)
        self.assertEqual(candidate.count("go build -mod=readonly ./..."), 4)
        self.assertIn("connectors/traefik/native_middleware", candidate)
        self.assertIn("connectors/traefik/composite_middleware", candidate)
        self.assertIn("connectors/traefik/response_observer", candidate)
        self.assertIn("Create and validate the bounded Go component candidate", candidate)
        self.assertIn("--validate-component-files", candidate)
        self.assertIn('--repository-root "$GITHUB_WORKSPACE"', candidate)
        self.assertIn("python3 ../../../scripts/update-go-components.py --apply-requirements --json", candidate)
        self.assertNotIn("go get", candidate)
        self.assertLess(
            candidate.index("--validate-component-files"),
            candidate.index("python3 ../../../scripts/update-go-components.py --apply-requirements --json"),
        )
        self.assertNotIn("--baseline-go-mod", candidate)
        self.assertNotIn("--candidate-go-mod", candidate)
        self.assertNotIn("--baseline-go-sum", candidate)
        self.assertNotIn("--candidate-go-sum", candidate)
        self.assertIn("git show HEAD:connectors/envoy/ext_proc/go.mod", candidate)
        self.assertIn("git show HEAD:connectors/envoy/ext_proc/go.sum", candidate)
        self.assertIn("printf '\\0'", candidate)
        self.assertIn("go mod tidy", candidate)
        self.assertIn("scripts/update-go-components.py", candidate)
        self.assertIn("component_go_mod_sha256", candidate)
        self.assertIn("component_go_sum_sha256", candidate)
        self.assertIn('scripts/update-go-version.py --check --expected-version "$CANDIDATE_VERSION" --json', candidate)
        self.assertIn("modsecurity_connector_tests.test_update_go_version", candidate)
        self.assertIn("modsecurity_connector_tests.test_update_go_components", candidate)
        self.assertIn("modsecurity_connector_tests.test_go_version_contract", candidate)

        publisher = jobs["create-go-update-pr"]
        self.assertEqual(
            job_permissions(publisher),
            {"contents": "write", "pull-requests": "write"},
        )
        self.assertNotIn("actions: write", publisher)
        self.assertIn("actions/setup-go@", publisher)
        self.assertIn("Set up independently validated Go candidate", publisher)
        self.assertIn("go-version: ${{ needs.resolve-go-release.outputs.latest_version }}", publisher)
        self.assertIn("GOTOOLCHAIN: local", publisher)
        self.assertIn("GOWORK: off", publisher)
        self.assertNotIn("submodules: recursive", publisher)
        self.assertNotIn("git submodule", publisher)
        self.assertNotIn("make ", publisher)
        self.assertNotIn("--force", publisher)
        self.assertNotIn("--force-with-lease", publisher)
        self.assertIn('python3 scripts/update-go-version.py --update --expected-version "$CANDIDATE_VERSION" --json', publisher)
        self.assertIn("--validate-component-files", publisher)
        self.assertIn("python3 ../../../scripts/update-go-components.py --apply-requirements --json", publisher)
        self.assertNotIn("go get", publisher)
        self.assertLess(
            publisher.index("--validate-component-files"),
            publisher.index("python3 ../../../scripts/update-go-components.py --apply-requirements --json"),
        )
        self.assertNotIn("--baseline-go-mod", publisher)
        self.assertNotIn("--candidate-go-mod", publisher)
        self.assertNotIn("--baseline-go-sum", publisher)
        self.assertNotIn("--candidate-go-sum", publisher)
        self.assertIn("git show HEAD:connectors/envoy/ext_proc/go.mod", publisher)
        self.assertIn("git show HEAD:connectors/envoy/ext_proc/go.sum", publisher)
        self.assertIn("printf '\\0'", publisher)
        self.assertNotIn("@latest", publisher)
        self.assertIn("VALIDATED_COMPONENT_GO_MOD_SHA256", publisher)
        self.assertIn("VALIDATED_COMPONENT_GO_SUM_SHA256", publisher)
        self.assertIn("--expected-go-mod-sha256", publisher)
        self.assertIn("--expected-go-sum-sha256", publisher)
        self.assertIn("UPDATE_BRANCH: automation/update-go-release", publisher)
        self.assertIn('PR_TITLE: "chore(ci): propose latest stable Go update"', publisher)
        self.assertIn("validate-go-release", publisher)
        self.assertIn("needs.validate-go-release.result == 'success'", job_if_expression(publisher))
        self.assertNotIn("1.26", publisher)
        self.assertIn("connectors/envoy/ext_proc/go.mod", publisher)
        self.assertIn("connectors/envoy/ext_proc/go.sum", publisher)
        self.assertIn("require_only_allowed_update_paths", publisher)
        self.assertIn("require_regular_file_updates", publisher)
        self.assertIn('git update-index --add --cacheinfo 100644 "$candidate_blob" "$candidate_path"', publisher)
        self.assertIn("git add --", publisher)
        self.assertNotIn("git add .", publisher)
        self.assertIn("git push origin \"$UPDATE_BRANCH\"", publisher)
        self.assertIn("--draft", publisher)
        self.assertIn("gh pr edit \"$existing_pr\"", publisher)
        self.assertIn("scripts/select-python-update-pr.py", publisher)
        self.assertIn(AUTO_MERGE_DISABLED_QUERY, publisher)
        self.assertIn('if [ "$auto_merge" != "null" ]; then', publisher)
        self.assertIn("## English", publisher)
        self.assertIn("## Deutsch", publisher)
        self.assertIn(
            "Module directives: only the fixed google.golang.org/grpc security bundle may change",
            publisher,
        )

    def test_go_candidate_pr_validation_is_read_only_and_tests_all_modules(self) -> None:
        text = self.workflow("validate-go-candidate.yml")
        candidate = self.jobs("validate-go-candidate.yml")["go-candidate"]
        self.assertEqual(job_permissions(candidate), {"contents": "read"})
        self.assertIn("  pull_request:", text)
        self.assertNotIn("pull_request_target", text)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("continue-on-error", text)
        self.assertNotIn("write", text)
        self.assertNotIn("create-go-update-pr", text)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", candidate)
        self.assertIn("persist-credentials: false", candidate)
        self.assertIn("submodules: false", candidate)
        self.assertIn("cache: false", candidate)
        self.assertIn("go-version-file: .go-version", candidate)
        self.assertIn("GOTOOLCHAIN: local", candidate)
        self.assertIn("GOWORK: off", candidate)
        for module in ("envoy/ext_proc", "traefik/native_middleware", "traefik/composite_middleware", "traefik/response_observer"):
            self.assertIn(f"connectors/{module}", candidate)
        for command in ("go mod tidy -diff", "go mod verify", "go test -mod=readonly ./...", "go test -race -mod=readonly ./...", "go vet -mod=readonly ./...", "go build -mod=readonly ./..."):
            self.assertIn(command, candidate)

    def test_sarif_upload_permissions_are_scoped(self) -> None:
        codeql = self.workflow("ci-security-codeql.yml")
        for job_name in ("actions", "envoy-go", "traefik-go", "bounded-c-cpp"):
            self.assertEqual(
                job_permissions(self.jobs("ci-security-codeql.yml")[job_name]),
                {"contents": "read", "security-events": "write"},
                job_name,
            )
        self.assertEqual(codeql.count("github/codeql-action/analyze@"), 4)

        osv = self.jobs("ci-security-osv.yml")["pull-request-diff"]
        self.assertEqual(job_permissions(osv), {"contents": "read", "security-events": "write"})
        self.assertIn("submodules: false", osv)
        self.assertIn("github.event.pull_request.base.sha", osv)
        self.assertIn("github.event.pull_request.head.sha", osv)
        self.assertIn("github/codeql-action/upload-sarif@", osv)

        scorecard_jobs = self.jobs("ci-security-scorecard.yml")
        self.assertEqual(job_permissions(scorecard_jobs["same-repository-pull-request"]), {"contents": "read"})
        self.assertIn("github.event.pull_request.head.sha", scorecard_jobs["same-repository-pull-request"])
        self.assertNotIn("upload-sarif", scorecard_jobs["same-repository-pull-request"])
        self.assertEqual(
            job_permissions(scorecard_jobs["default-branch"]),
            {"contents": "read", "security-events": "write"},
        )
        self.assertIn("github/codeql-action/upload-sarif@", scorecard_jobs["default-branch"])

    def test_permission_contract_fixtures_reject_unsafe_and_accept_safe(self) -> None:
        safe = (PERMISSION_FIXTURES / "safe.yml").read_text(encoding="utf-8")
        unsafe = (PERMISSION_FIXTURES / "unsafe.yml").read_text(encoding="utf-8")
        self.assertEqual(fixture_violations(safe), set())
        self.assertEqual(
            fixture_violations(unsafe),
            {
                "pull_request_target",
                "top_level_permissions",
                "secret_reference",
                "persisted_credentials",
                "privileged_submodule_execution",
            },
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
