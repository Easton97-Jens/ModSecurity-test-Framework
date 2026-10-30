"""Pinned Framework ownership of private CI-tool candidate test provisioning.

The product updater retains candidate algorithms and publication authority.
Only this connector-test adapter copies/admits tests and runs candidate gates.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

from modsecurity_test_framework.connector_context import (
    ConnectorContext, connector_root, test_root, source_path, load_source,
)
from .lib.active_test_inventory import load_inventory

product = load_source(source_path("ci/tools/update-workflow-tools.py"))

PROPOSED_TREE_BASELINE_PATHS = frozenset(
    {
        "Makefile",
        ".python-version",
        ".go-version",
        ".github/dependabot.yml",
        "requirements-ci.lock",
        "requirements-ci-build.lock",
        "requirements-dev.txt",
        "connectors/envoy/ext_proc/go.mod",
        "connectors/traefik/composite_middleware/go.mod",
        "connectors/traefik/native_middleware/go.mod",
        "connectors/traefik/response_observer/go.mod",
        "connectors/envoy/config/envoy-ext-proc-versions.env",
        "connectors/haproxy/htx-overlay/version-contract.json",
        "connectors/lighttpd/SOURCE_MAP.json",
        "connectors/lighttpd/lighttpd-version.contract",
        "connectors/nginx/harness/run_exact_head_use_error_log.sh",
        "connectors/nginx/harness/run_github_hosted_functional_a.py",
        "connectors/nginx/harness/nginx_smoke.conf",
        "connectors/nginx/harness/run_nginx_smoke.sh",
        "ci/checks/evidence/check-runtime-producer-readiness.py",
        "ci/checks/common/check-python-version-contract.py",
        "ci/lib/framework_revision_pins.py",
        "ci/lib/workflow_action_pins.py",
        "ci/tooling/project-versions.lock.json",
        "ci/fixtures/workflow-permission-contract/safe.yml",
        "ci/fixtures/workflow-permission-contract/unsafe.yml",
        "ci/fixtures/zizmor/safe.yml",
        "ci/fixtures/zizmor/insecure.yml",
        "ci/provisioning/components/prepare-runtime-components.py",
        "ci/requirements/update-submodules-validation-linux-x86_64.txt",
        "ci/runtime/broker/nginx_root_broker.py",
        "ci/runtime/broker/protected_nginx_broker_caller.py",
        "ci/runtime/lifecycle/run-verified-report-run.py",
        "ci/runtime/lifecycle/run-with-crs-no-mrts.sh",
        "ci/runtime/lifecycle/prepare-with-crs-no-mrts-upload.py",
        "ci/tools/fetch_security_tool.py",
        "ci/tools/lint_workflows.py",
        "ci/tools/lint_installed_workflows.py",
        "ci/tools/install-ci-dependencies.py",
        "ci/tools/read-framework-revisions.py",
        "ci/tools/sync-project-versions.py",
        "ci/tools/prepare-readonly-submodule-validation-sandbox.py",
        "ci/tools/run-readonly-submodule-validation-namespace.py",
        "ci/tools/sync-framework-component-versions.py",
        "ci/tools/validate-submodule-candidate-state.py",
        "ci/tools/verify-framework-candidate-contract.py",
        "ci/tools/update-workflow-tools.py",
        "scripts/generate_compiler_guides.py",
        "scripts/version_updater_common.py",
        "scripts/update-python-version.py",
        "scripts/update-go-version.py",
        "tests/framework_component_fixture.py",
        "tests/framework_sha_fixture.py",
        "tests/test_framework_revision_pins.py",
        "tests/test_project_toolchain_pins.py",
        "tests/version_updater_test_support.py",
        "tests/ci_security/test_update_workflow_tools.py",
        "tests/test_compiler_guides.py",
        "tests/test_prepare_runtime_components.py",
        "tests/test_verify_framework_candidate_contract.py",
        "tests/test_ci_security_workflows.py",
        "tests/test_lint_workflows.py",
        "tests/test_install_ci_dependencies.py",
        "tests/test_python_version_contract.py",
        "tests/test_nginx_exact_head_gate_contract.py",
        "tests/test_trusted_lighttpd_namespace_dispatch_workflow.py",
        "tests/test_prepare_readonly_submodule_validation_sandbox.py",
        "tests/test_run_readonly_submodule_validation_namespace.py",
        "tests/test_update_framework_versions.py",
        "tests/test_update_submodules_local_git.py",
        "tests/test_validate_submodule_candidate_state.py",
    }
)

PROPOSED_TREE_ACTIVE_RUNTIME_PATHS = frozenset(
    {
        "config/testing/active-cases.json",
        "ci/lib/active_test_inventory.py",
        "ci/tools/run-active-tests.py",
        "scripts/update-go-components.py",
        "tests/__init__.py",
        "ci/lib/active_inventory_updates.py",
        "reports/testing/test-selection-archive.generated.json",
    }
)

def proposed_validation_root() -> Path:
    """Create one private, bounded temporary root for candidate-only writes."""
    runner_root = product.runner_temp_root()
    proposed = Path(tempfile.mkdtemp(prefix='modsecurity-conector-workflow-tool-proposed-', dir=runner_root))
    mode = proposed.lstat().st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise product.UpdateError('proposed validation root must be a non-symlink directory')
    if proposed.parent != runner_root or proposed.stat().st_uid != os.geteuid():
        raise product.UpdateError('proposed validation root must be runner-owned')
    proposed.chmod(448)
    return proposed

def admitted_validation_inventory(root: Path) -> Any:
    """Admit canonical tests or an explicitly isolated legacy data fixture."""
    try:
        return load_inventory(root)
    except (OSError, ValueError) as error:
        raise product.UpdateError("proposed-tree inputs require a valid complete active inventory") from error


@contextmanager
def selected_checkout(root: Path):
    original = {key: os.environ.get(key) for key in ("CONNECTOR_ROOT", "CONNECTOR_REVISION")}
    revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    os.environ.update(CONNECTOR_ROOT=str(root), CONNECTOR_REVISION=revision)
    try:
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _resolve_update_input(source_root, relative, actual_checkout):
    """Resolve Product relocations while leaving Framework-owned inputs out of the copy."""
    if actual_checkout:
        source = source_path(relative, root=source_root)
        if source.is_relative_to(test_root()):
            return None
        # The reviewed source map also records product-owned relocations.
        # Copy those files at their explicit current Product paths so the
        # private checkout retains the same ownership contract.
        try:
            relative = source.relative_to(source_root)
        except ValueError as error:
            raise product.UpdateError("proposed source is outside its explicit owner") from error
        source = product.resolve_regular_file(source_root, relative)
    else:
        source = product.resolve_regular_file(source_root, relative)
    return relative, source


def _copy_update_input(source, destination_root, relative):
    """Materialize one reviewed regular input exclusively with private output modes."""
    destination = destination_root / relative
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise product.UpdateError(f"proposed validation path already exists: {relative}")
    with source.open("rb") as input_file, destination.open("xb") as output_file:
        shutil.copyfileobj(input_file, output_file)
    destination.chmod(0o600)


def copy_update_inputs(source_root: Path, destination_root: Path) -> None:
    """Copy only reviewed inputs, with a valid private source identity for live tests."""
    inventory = admitted_validation_inventory(source_root)
    bound_sources = {name for execution in inventory.executions for name in execution["sources"]}
    inputs = product.ALLOWED_UPDATE_PATHS | PROPOSED_TREE_BASELINE_PATHS | PROPOSED_TREE_ACTIVE_RUNTIME_PATHS | bound_sources
    actual_checkout = source_root.resolve() == connector_root()
    if actual_checkout:
        # No checkout/filter/hook execution. Objects remain read-only and only
        # the reviewed file allowlist below is materialized into this tree.
        result = subprocess.run(["git", "clone", "--shared", "--no-checkout", "--no-hardlinks",
                                 str(source_root), str(destination_root)],
                                capture_output=True, text=True, check=False, timeout=60)
        if result.returncode:
            raise product.UpdateError("cannot establish private candidate source identity")
    materialized = set()
    for relative_text in sorted(inputs):
        relative = Path(relative_text)
        resolved = _resolve_update_input(source_root, relative, actual_checkout)
        if resolved is None:
            continue
        relative, source = resolved
        if relative in materialized:
            continue
        _copy_update_input(source, destination_root, relative)
        materialized.add(relative)
    if actual_checkout:
        with selected_checkout(destination_root):
            admitted_validation_inventory(destination_root)
    else:
        admitted_validation_inventory(destination_root)


def run_proposed_tree_contract_checks(proposed_root: Path) -> None:
    """Run the existing Connector CI-security baseline against the temp tree."""
    product.resolve_regular_file(proposed_root, Path('Makefile'))
    with tempfile.TemporaryDirectory(
        prefix="modsecurity-conector-workflow-tool-results-", dir=product.runner_temp_root()
    ) as results_root:
        environment = dict(os.environ, CONNECTOR_TEST_OUTPUT_ROOT=results_root)
        result = subprocess.run(['make', f'PYTHON={sys.executable}', 'ON_DEMAND_TESTS=0', 'check-ci-security-contract'], cwd=proposed_root, env=environment, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            output = f'{result.stdout}{result.stderr}'.strip()
            raise product.UpdateError(f'proposed workflow-tool candidate fails Connector CI security contract: {output}')

def run_proposed_workflow_lint(proposed_root: Path, arguments: list[str], *, expected_returncode: int=0) -> None:
    """Require a bounded lint result; tool failures never satisfy negative fixtures."""
    try:
        result = subprocess.run(arguments, cwd=proposed_root, check=False, capture_output=True, text=True, timeout=180, shell=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise product.UpdateError(f'proposed workflow-tool lint could not complete: {exc}') from exc
    if result.returncode != expected_returncode:
        output = f'{result.stdout}{result.stderr}'.strip()[:8000]
        raise product.UpdateError(f'proposed workflow-tool lint failed ({Path(arguments[0]).name}, expected {expected_returncode}, got {result.returncode}): {output}')

def run_proposed_tree_workflow_lints(proposed_root: Path) -> None:
    """Execute the proposed checksum-verified tools before publishing any update."""
    _lock_path, lock, _lock_digest = product.load_lock(proposed_root)
    fetcher = product.load_fetcher_module()
    tools_root = proposed_root / '.candidate-security-tools'
    tools_root.mkdir(mode=448)
    executables: dict[str, Path] = {}
    for name in ('actionlint', 'zizmor'):
        record = lock['tools'].get(name)
        if not isinstance(record, dict):
            raise product.UpdateError(f'proposed lock is missing workflow lint tool {name!r}')
        downloader_record = {'version': record.get('version'), 'asset': record.get('asset'), 'url': record.get('asset_url'), 'sha256': record.get('sha256'), 'executable': record.get('executable'), 'upstream': record.get('upstream')}
        try:
            executable = fetcher.fetch_record(name, downloader_record, tools_root / name)
            executables[name] = product.resolve_regular_file(proposed_root, executable.relative_to(proposed_root))
        except (OSError, ValueError) as exc:
            raise product.UpdateError(f'proposed workflow lint tool {name!r} verification failed: {exc}') from exc
    permission_fixtures = ('ci/fixtures/workflow-permission-contract/safe.yml', 'ci/fixtures/workflow-permission-contract/unsafe.yml')
    lint_wrapper = source_path('ci/tools/lint_workflows.py')
    run_proposed_workflow_lint(proposed_root, [sys.executable, '-P', str(lint_wrapper),
                                             '--candidate-tree', '--candidate-root', str(proposed_root)])
    zizmor = [str(executables['zizmor']), '--offline']
    run_proposed_workflow_lint(proposed_root, [*zizmor, '.github/workflows'])
    for fixture, expected_returncode in (('ci/fixtures/zizmor/insecure.yml', 14), ('ci/fixtures/zizmor/safe.yml', 0), (permission_fixtures[1], 14), (permission_fixtures[0], 0)):
        fixture_path = source_path(fixture)
        run_proposed_workflow_lint(proposed_root, [*zizmor, str(fixture_path)], expected_returncode=expected_returncode)

def validate_proposed_tree(root: Path, candidate: dict[str, Any]) -> None:
    """Apply a candidate only in RUNNER_TEMP, then validate its resulting tree."""
    source_root = product.resolve_root(root)
    proposed_root = proposed_validation_root()
    try:
        copy_update_inputs(source_root, proposed_root)
        product.apply_candidate(proposed_root, candidate)
        if (proposed_root / '.git').exists():
            with selected_checkout(proposed_root):
                run_proposed_tree_contract_checks(proposed_root)
                run_proposed_tree_workflow_lints(proposed_root)
        else:
            run_proposed_tree_contract_checks(proposed_root)
            run_proposed_tree_workflow_lints(proposed_root)
    finally:
        shutil.rmtree(proposed_root, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--candidate-stdin", action="store_true", required=True)
    parser.parse_args()
    context = ConnectorContext.from_environment()
    data = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise product.UpdateError("candidate exceeds bounded validation input")
    candidate = json.loads(data)
    validate_proposed_tree(context.connector, candidate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
