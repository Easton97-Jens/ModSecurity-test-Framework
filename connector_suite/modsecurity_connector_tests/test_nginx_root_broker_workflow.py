"""Static trust-boundary contract for the immutable broker workflow."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = connector_root()
WORKFLOW = source_path('.github/workflows/nginx-root-broker.yml', root=ROOT)
NGINX_CONFIG = source_path('connectors/nginx/config', root=ROOT)


def step_block(workflow: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = workflow.index(marker)
    end = workflow.find("\n      - name:", start + len(marker))
    return workflow[start:] if end == -1 else workflow[start:end]


def binding_failure_errors(workflow: str) -> list[str]:
    """Return static violations that could run work after caller binding fails."""

    errors: list[str] = []
    marker = "      - name: Validate immutable protected caller workflow object\n"
    if marker not in workflow:
        return ["missing caller binding step"]
    before_binding = workflow[: workflow.index(marker)]
    binding_step = step_block(workflow, "Validate immutable protected caller workflow object")
    if "continue-on-error:" in binding_step:
        errors.append("caller binding step can continue after failure")
    if "\n        if:" in binding_step:
        errors.append("caller binding step can be skipped")
    if "set -euo pipefail" not in binding_step:
        errors.append("caller binding step lacks fail-fast shell options")
    if (
        "set +e" in binding_step
        or "set +o errexit" in binding_step
        or "||" in binding_step
    ):
        errors.append("caller binding command can suppress a failure")
    expected_command_start = (
        "          python3 -I ci/runtime/broker/nginx_root_broker.py validate-caller-workflow \\\n"
    )
    if expected_command_start not in binding_step:
        errors.append("caller binding command has an unexpected invocation")
    expected_terminal_command = '            --framework-sha "$EXPECTED_FRAMEWORK_SHA"'
    if not binding_step.rstrip().endswith(expected_terminal_command):
        errors.append("caller binding command is not terminal")
    for name in ("BROKER_MANIFEST", "BROKER_PROJECTION", "BROKER_ARTIFACT_EVIDENCE"):
        if f"{name}=" in before_binding:
            errors.append(f"{name} is recorded before caller binding")
    for name in (
        "Download declarative caller manifest",
        "Build only trusted protected-source artifacts without root",
        "Build a protected immutable OWASP CRS bundle without root",
        "Produce a non-executable trusted candidate manifest",
        "Admit only verified artifacts into the root-owned broker root",
        "Run fixed root-only NGINX actions",
    ):
        if "\n        if:" in step_block(workflow, name):
            errors.append(f"{name} can bypass a failed caller binding")
    guarded_steps = {
        "Stage the fixed root-to-user evidence outside the cleanup root": "env.BROKER_PROJECTION != ''",
        "Stop and verify root cleanup": "env.BROKER_MANIFEST != ''",
        "Upload bounded root-to-user evidence": "env.BROKER_ARTIFACT_EVIDENCE != ''",
    }
    for name, required_guard in guarded_steps.items():
        block = step_block(workflow, name)
        if "if: ${{ always() &&" not in block or required_guard not in block:
            errors.append(f"{name} has no bounded post-admission guard")
    return errors


def python_version_materialization_errors(workflow: str) -> list[str]:
    """Return static violations for the broker-controlled Python version file."""

    required_steps = (
        "Verify protected source, caller commit, and dependency identity",
        "Materialize verified broker Python version contract",
        "Set up protected broker Python",
        "Verify Python interpreter contract",
        "Validate immutable protected caller workflow object",
    )
    if any(f"      - name: {name}\n" not in workflow for name in required_steps):
        return ["missing protected Python-version workflow step"]

    errors: list[str] = []
    source_step = step_block(
        workflow, "Verify protected source, caller commit, and dependency identity"
    )
    materialization_step = step_block(
        workflow, "Materialize verified broker Python version contract"
    )
    expected_materialization_step = "\n".join(
        (
            "      - name: Materialize verified broker Python version contract",
            "        working-directory: broker-src",
            "        run: |",
            "          set -euo pipefail",
            "          source_path=.python-version",
            '          destination="$GITHUB_WORKSPACE/.python-version"',
            '          test ! -L "$source_path"',
            '          test -f "$source_path"',
            '          expected=$(git rev-parse "$BROKER_SHA:$source_path")',
            '          actual=$(git hash-object "$source_path")',
            '          test "$actual" = "$expected"',
            '          test ! -e "$destination"',
            '          test ! -L "$destination"',
            '          install -m 0644 "$source_path" "$destination"',
            '          test ! -L "$destination"',
            '          cmp -- "$source_path" "$destination"',
        )
    )
    if materialization_step.rstrip() != expected_materialization_step:
        errors.append("protected Python-version materialization has an unexpected command surface")
    if "continue-on-error:" in materialization_step:
        errors.append("protected Python-version materialization can continue after failure")
    if "\n        if:" in materialization_step:
        errors.append("protected Python-version materialization can be skipped")
    if "set -euo pipefail" not in materialization_step:
        errors.append("protected Python-version materialization lacks fail-fast shell options")
    if (
        "set +e" in materialization_step
        or "set +o errexit" in materialization_step
        or "||" in materialization_step
    ):
        errors.append("protected Python-version materialization can suppress a failure")
    if "verify_broker_source .python-version" not in source_step:
        errors.append("broker Python version blob is not verified before materialization")
    for required in (
        "source_path=.python-version",
        'destination="$GITHUB_WORKSPACE/.python-version"',
        'expected=$(git rev-parse "$BROKER_SHA:$source_path")',
        'actual=$(git hash-object "$source_path")',
        'test ! -e "$destination"',
        'test ! -L "$destination"',
        'install -m 0644 "$source_path" "$destination"',
        'cmp -- "$source_path" "$destination"',
    ):
        if required not in materialization_step:
            errors.append(f"missing protected Python-version materialization control: {required}")

    source_verification = workflow.index("verify_broker_source .python-version")
    materialization = workflow.index("Materialize verified broker Python version contract")
    setup = workflow.index("Set up protected broker Python")
    verifier = workflow.index("Verify Python interpreter contract")
    caller_binding = workflow.index("Validate immutable protected caller workflow object")
    if not source_verification < materialization < setup < verifier < caller_binding:
        errors.append("protected Python-version materialization has an unsafe order")
    return errors


def runtime_component_snapshot_contract_errors(workflow: str) -> list[str]:
    """Return static violations for the fixed protected build selectors."""

    build_step_name = "Build only trusted protected-source artifacts without root"
    required_snapshot_selection = (
        "          RUNTIME_COMPONENT_SNAPSHOT_CONTRACT: protected-nginx-broker"
    )
    required_rpath_selection = '          NGX_IGNORE_RPATH: "YES"'
    if f"      - name: {build_step_name}\n" not in workflow:
        return ["missing protected build step"]

    errors: list[str] = []
    build_step = step_block(workflow, build_step_name)
    if workflow.count(required_snapshot_selection) != 1:
        errors.append("snapshot selector is not unique and fixed")
    if required_snapshot_selection not in build_step:
        errors.append("snapshot selector is outside the trusted build step")
    if workflow.count(required_rpath_selection) != 1:
        errors.append("RPATH selector is not unique and fixed")
    if required_rpath_selection not in build_step:
        errors.append("RPATH selector is outside the trusted build step")
    if "\n        if:" in build_step:
        errors.append("trusted build step can conditionally select a snapshot contract")
    if "continue-on-error:" in build_step:
        errors.append("trusted build step can continue after snapshot preparation failure")
    if "RUNTIME_COMPONENT_SNAPSHOT_CONTRACT: ${{" in workflow:
        errors.append("snapshot selector accepts a mutable expression")
    if "NGX_IGNORE_RPATH: ${{" in workflow:
        errors.append("RPATH selector accepts a mutable expression")
    if "inputs.runtime_component_snapshot_contract" in workflow:
        errors.append("snapshot selector accepts a caller input")
    if "inputs.ngx_ignore_rpath" in workflow:
        errors.append("RPATH selector accepts a caller input")
    if required_snapshot_selection in workflow and required_rpath_selection in workflow:
        snapshot_selection = workflow.index(required_snapshot_selection)
        rpath_selection = workflow.index(required_rpath_selection)
        fetch_dependencies = workflow.index("make fetch-deps")
        prepare_from_snapshot = workflow.index("prepare-from-snapshot")
        if not snapshot_selection < fetch_dependencies < prepare_from_snapshot:
            errors.append("snapshot selector does not precede dependency and candidate preparation")
        if not rpath_selection < fetch_dependencies < prepare_from_snapshot:
            errors.append("RPATH selector does not precede dependency and candidate preparation")
    return errors


def crs_fetch_umask_contract_errors(workflow: str) -> list[str]:
    """Return violations of the isolated CRS-fetch mode contract."""

    step_name = "Build a protected immutable OWASP CRS bundle without root"
    if f"      - name: {step_name}\n" not in workflow:
        return ["missing protected CRS bundle step"]

    errors: list[str] = []
    step = step_block(workflow, step_name)
    fetch_command = "sh modules/ModSecurity-test-Framework/ci/provisioning/fetch-crs.sh"
    required_sequence = "\n".join(
        (
            "          umask 077",
            '          case "$(umask)" in',
            "            077|0077) ;;",
            "            *) exit 77 ;;",
            "          esac",
            "          verify_broker_source .github/workflows/nginx-root-broker.yml",
            "          verify_broker_source ci/runtime/broker/nginx_root_broker.py",
            '          export CONNECTOR_ROOT="$PWD" REPO_ROOT="$PWD"',
            "          . modules/ModSecurity-test-Framework/ci/lib/common.sh",
            "          . ci/runtime/lifecycle/prepare-fresh-crs-source.sh",
            "          if (",
            "            umask 022",
            '            case "$(umask)" in',
            "              022|0022) ;;",
            "              *) exit 77 ;;",
            "            esac",
            f"            {fetch_command}",
            "          ); then",
            "            fetch_status=0",
            "          else",
            "            fetch_status=$?",
            "          fi",
            '          case "$(umask)" in',
            "            077|0077) ;;",
            "            *) exit 77 ;;",
            "          esac",
            '          if [ "$fetch_status" -ne 0 ]; then',
            '            exit "$fetch_status"',
            "          fi",
        )
    )
    if required_sequence not in step:
        errors.append("CRS fetch umask scope or restoration sequence is unexpected")
    if workflow.count(fetch_command) != 1 or step.count(fetch_command) != 1:
        errors.append("CRS fetch command is not unique and fixed")
    if workflow.count("umask 022") != 1 or step.count("umask 022") != 1:
        errors.append("CRS fetch umask is not uniquely scoped")
    if "chmod -R" in step:
        errors.append("CRS source modes are normalized recursively")
    return errors


def run_failed_crs_fetch_umask_probe(workflow: str) -> tuple[int, str]:
    """Run the workflow's fetch-status branch with a hermetic failed fetch."""

    step = step_block(workflow, "Build a protected immutable OWASP CRS bundle without root")
    fetch_command = "sh modules/ModSecurity-test-Framework/ci/provisioning/fetch-crs.sh"
    start = step.index("          if (\n")
    end = step.index("          verify_broker_source", start)
    failure_branch = textwrap.dedent(step[start:end]).replace(fetch_command, "false", 1)

    with tempfile.TemporaryDirectory() as temporary_directory:
        umask_trace = Path(temporary_directory) / "outer-umask"
        probe = "\n".join(
            (
                "set -u",
                "umask 077",
                'trap \'umask > "$UMASK_TRACE"\' EXIT',
                failure_branch,
            )
        )
        result = subprocess.run(
            ["bash", "-c", probe],
            check=False,
            capture_output=True,
            env={"LC_ALL": "C", "PATH": os.defpath, "UMASK_TRACE": str(umask_trace)},
            text=True,
        )
        return result.returncode, umask_trace.read_text(encoding="utf-8").strip()


def nginx_explicit_library_rpath_contract_errors(config: str) -> list[str]:
    """Return violations of the protected build's explicit no-RPATH opt-in."""

    required_branch = "\n".join(
        (
            '        if [ "$NGX_IGNORE_RPATH" = "YES" ]; then',
            '            ngx_feature_libs="-L$MODSECURITY_LIB -lmodsecurity $YAJL_EXTRA"',
            '        elif [ $NGX_RPATH = YES ]; then',
        )
    )
    errors: list[str] = []
    if config.count(required_branch) != 1:
        errors.append("explicit ModSecurity library path does not honor the no-RPATH opt-in first")
    if config.find(required_branch) > config.find("    . auto/feature", config.find("MODSECURITY_INC")):
        errors.append("no-RPATH opt-in is outside the explicit ModSecurity library branch")
    return errors


class TrustedNginxRootBrokerWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_is_reusable_read_only_and_refuses_pr_trigger_modes(self) -> None:
        self.assertIn("  workflow_call:\n", self.workflow)
        self.assertNotIn("  pull_request:", self.workflow)
        self.assertNotIn("  pull_request_target:", self.workflow)
        self.assertIn("\npermissions: {}\n", self.workflow)
        self.assertIn("    permissions:\n      contents: read\n", self.workflow)
        self.assertIn("github.event_name == 'workflow_dispatch'", self.workflow)
        self.assertNotIn("github.event_name == 'workflow_dispatch' || github.event_name == 'schedule'", self.workflow)
        self.assertIn("github.repository == 'Easton97-Jens/ModSecurity-conector'", self.workflow)
        self.assertIn("github.event.repository.fork == false", self.workflow)
        self.assertIn("github.ref == 'refs/heads/master'", self.workflow)
        self.assertIn("github.event.repository.default_branch == 'master'", self.workflow)
        self.assertNotIn("secrets.", self.workflow)
        self.assertNotIn("id-token: write", self.workflow)

    def test_broker_source_is_immutable_and_bound_to_the_protected_caller_commit(self) -> None:
        self.assertIn("ACTUAL_CALLER_WORKFLOW_REF: ${{ github.workflow_ref }}", self.workflow)
        self.assertIn(
            "EXPECTED_CALLER_WORKFLOW_REF: Easton97-Jens/ModSecurity-conector/.github/workflows/run-protected-nginx-root-broker.yml@refs/heads/master",
            self.workflow,
        )
        self.assertIn('test "$ACTUAL_CALLER_WORKFLOW_REF" = "$EXPECTED_CALLER_WORKFLOW_REF"', self.workflow)
        self.assertNotIn("EXPECTED_WORKFLOW_REF:", self.workflow)
        self.assertIn("CALLER_SHA: ${{ github.sha }}", self.workflow)
        self.assertIn("CALLER_WORKFLOW_SHA: ${{ github.workflow_sha }}", self.workflow)
        for expected in (
            'test "$CALLER_REPOSITORY" = Easton97-Jens/ModSecurity-conector',
            'test "$CALLER_REF" = refs/heads/master',
            'test "$CALLER_EVENT_NAME" = workflow_dispatch',
            'test "$CALLER_FORK" = false',
            'test "$CALLER_DEFAULT_BRANCH" = master',
            'test "$CALLER_WORKFLOW_SHA" = "$CALLER_SHA"',
            'git cat-file -e "$CALLER_SHA^{commit}"',
            'git merge-base --is-ancestor "$CALLER_SHA" FETCH_HEAD',
            'git merge-base --is-ancestor "$BROKER_SHA" "$CALLER_SHA"',
        ):
            self.assertIn(expected, self.workflow)
        self.assertIn("repository: Easton97-Jens/ModSecurity-conector", self.workflow)
        self.assertIn("ref: ${{ inputs.protected_broker_sha }}", self.workflow)
        self.assertIn("path: broker-src", self.workflow)
        self.assertIn("fetch-depth: 0", self.workflow)
        self.assertIn("submodules: recursive", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertIn("clean: true", self.workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "$BROKER_SHA"', self.workflow)
        self.assertIn('git merge-base --is-ancestor "$BROKER_SHA" FETCH_HEAD', self.workflow)
        self.assertIn('git ls-tree "$BROKER_SHA" -- modules/ModSecurity-test-Framework', self.workflow)
        self.assertIn('git rev-parse "$BROKER_SHA:modules/ModSecurity-test-Framework"', self.workflow)
        self.assertIn('test "$framework_gitlink" = "$EXPECTED_FRAMEWORK_SHA"', self.workflow)
        self.assertIn('git submodule status --recursive', self.workflow)
        self.assertIn('tools/MRTS status --porcelain', self.workflow)
        self.assertIn("verify_broker_source .github/workflows/nginx-root-broker.yml", self.workflow)
        self.assertIn('git rev-parse "$BROKER_SHA:$source_path"', self.workflow)
        self.assertIn("git hash-object \"$source_path\"", self.workflow)
        self.assertIn("verify_broker_source ci/runtime/broker/nginx_root_broker.py", self.workflow)
        self.assertIn("verify_broker_source .python-version", self.workflow)
        self.assertIn("Materialize verified broker Python version contract", self.workflow)
        self.assertIn('destination="$GITHUB_WORKSPACE/.python-version"', self.workflow)
        self.assertIn('test ! -e "$destination"', self.workflow)
        self.assertIn('install -m 0644 "$source_path" "$destination"', self.workflow)
        self.assertIn("id: setup-python", self.workflow)
        self.assertIn("python-version-file: .python-version", self.workflow)
        self.assertIn("Verify Python interpreter contract", self.workflow)
        self.assertIn("Validate immutable protected caller workflow object", self.workflow)
        self.assertIn("validate-caller-workflow", self.workflow)
        self.assertIn('"$CALLER_SHA"', self.workflow)
        self.assertIn("/usr/bin/python3 -I ci/runtime/broker/nginx_root_broker.py", self.workflow)
        self.assertNotIn("@master", self.workflow)
        self.assertNotIn("@fix/f-gs-003-pin-nginx-full-smoke", self.workflow)
        self.assertNotIn("uses: ./", self.workflow)

    def test_binding_closes_before_artifacts_build_candidate_or_root(self) -> None:
        binding = self.workflow.index("Validate immutable protected caller workflow object")
        for later in (
            "Download declarative caller manifest",
            "Build only trusted protected-source artifacts without root",
            "make fetch-deps",
            "Produce a non-executable trusted candidate manifest",
            "Admit only verified artifacts into the root-owned broker root",
            "sudo -- /usr/bin/python3 -I ci/runtime/broker/nginx_root_broker.py action",
        ):
            self.assertLess(binding, self.workflow.index(later), later)
        for action in (
            "config-test",
            "start",
            "verify-runtime-profile",
            "verify-master-worker-identity",
            "stop",
            "project-evidence",
        ):
            self.assertIn(
                "\n".join(
                    (
                        "          verify_broker_source",
                        "          sudo -- /usr/bin/python3 -I ci/runtime/broker/nginx_root_broker.py "
                        f"action --action {action}",
                    )
                ),
                self.workflow,
            )
        self.assertIn("verify_broker_source\n          manifest=$(sudo -- /usr/bin/python3 -I", self.workflow)
        self.assertIn("verify_broker_source\n          set +e\n          sudo -- /usr/bin/python3 -I", self.workflow)
        self.assertIn(
            "set -e\n          verify_broker_source\n          set +e\n          sudo -- /usr/bin/python3 -I",
            self.workflow,
        )

    def test_verified_broker_python_version_precedes_setup_and_python_use(self) -> None:
        self.assertEqual(python_version_materialization_errors(self.workflow), [])
        materialization_start = self.workflow.index(
            "      - name: Materialize verified broker Python version contract\n"
        )
        setup_start = self.workflow.index("      - name: Set up protected broker Python\n")
        verifier_start = self.workflow.index("      - name: Verify Python interpreter contract\n")
        materialization_after_setup = (
            self.workflow[:materialization_start]
            + self.workflow[setup_start:verifier_start]
            + self.workflow[materialization_start:setup_start]
            + self.workflow[verifier_start:]
        )
        mutations = {
            "uses workspace source": (
                "source_path=.python-version",
                "source_path=$GITHUB_WORKSPACE/.python-version",
            ),
            "accepts an existing destination": ('test ! -e "$destination"', "true"),
            "materialization error can continue": (
                "      - name: Materialize verified broker Python version contract\n"
                "        working-directory:",
                "      - name: Materialize verified broker Python version contract\n"
                "        continue-on-error: true\n"
                "        working-directory:",
            ),
            "materialization can be skipped": (
                "      - name: Materialize verified broker Python version contract\n"
                "        working-directory:",
                "      - name: Materialize verified broker Python version contract\n"
                "        if: ${{ false }}\n"
                "        working-directory:",
            ),
            "materialization disables errexit": (
                "      - name: Materialize verified broker Python version contract\n"
                "        working-directory: broker-src\n"
                "        run: |\n"
                "          set -euo pipefail\n",
                "      - name: Materialize verified broker Python version contract\n"
                "        working-directory: broker-src\n"
                "        run: |\n"
                "          set -euo pipefail\n"
                "          set +o errexit\n",
            ),
            "materialization suppresses a failed destination check": (
                'test ! -e "$destination"',
                'test ! -e "$destination" || true',
            ),
            "materialization absorbs a failed destination check": (
                'test ! -e "$destination"',
                'if test ! -e "$destination"; then :; else :; fi',
            ),
        }
        for name, (original, replacement) in mutations.items():
            with self.subTest(name=name):
                self.assertIn(original, self.workflow)
                mutated = self.workflow.replace(original, replacement, 1)
                self.assertNotEqual(python_version_materialization_errors(mutated), [])
        self.assertNotEqual(
            python_version_materialization_errors(materialization_after_setup), []
        )

    def test_binding_failure_cannot_create_candidate_or_broker_evidence(self) -> None:
        self.assertEqual(binding_failure_errors(self.workflow), [])
        mutations = {
            "manifest state before binding": (
                '          test "$ACTUAL_CALLER_WORKFLOW_REF" = "$EXPECTED_CALLER_WORKFLOW_REF"',
                '          echo "BROKER_MANIFEST=unsafe" >> "$GITHUB_ENV"\n'
                '          test "$ACTUAL_CALLER_WORKFLOW_REF" = "$EXPECTED_CALLER_WORKFLOW_REF"',
            ),
            "binding error can continue": (
                "      - name: Validate immutable protected caller workflow object\n"
                "        working-directory:",
                "      - name: Validate immutable protected caller workflow object\n"
                "        continue-on-error: true\n"
                "        working-directory:",
            ),
            "binding can be skipped": (
                "      - name: Validate immutable protected caller workflow object\n"
                "        working-directory:",
                "      - name: Validate immutable protected caller workflow object\n"
                "        if: ${{ false }}\n"
                "        working-directory:",
            ),
            "binding command suppresses an error": (
                '            --framework-sha "$EXPECTED_FRAMEWORK_SHA"',
                '            --framework-sha "$EXPECTED_FRAMEWORK_SHA" || true',
            ),
            "binding command disables errexit": (
                "      - name: Validate immutable protected caller workflow object\n"
                "        working-directory: broker-src\n"
                "        run: |\n"
                "          set -euo pipefail\n",
                "      - name: Validate immutable protected caller workflow object\n"
                "        working-directory: broker-src\n"
                "        run: |\n"
                "          set -euo pipefail\n"
                "          set +o errexit\n",
            ),
            "binding command negates an error": (
                "          python3 -I ci/runtime/broker/nginx_root_broker.py validate-caller-workflow \\\n",
                "          ! python3 -I ci/runtime/broker/nginx_root_broker.py validate-caller-workflow \\\n",
            ),
            "binding command is not terminal": (
                '            --framework-sha "$EXPECTED_FRAMEWORK_SHA"',
                '            --framework-sha "$EXPECTED_FRAMEWORK_SHA"\n          true',
            ),
            "artifact download always runs": (
                "      - name: Download declarative caller manifest\n        uses:",
                "      - name: Download declarative caller manifest\n"
                "        if: ${{ always() }}\n        uses:",
            ),
            "candidate build always runs": (
                "      - name: Build only trusted protected-source artifacts without root\n"
                "        working-directory:",
                "      - name: Build only trusted protected-source artifacts without root\n"
                "        if: ${{ always() }}\n        working-directory:",
            ),
            "candidate root admission always runs": (
                "      - name: Admit only verified artifacts into the root-owned broker root\n"
                "        working-directory:",
                "      - name: Admit only verified artifacts into the root-owned broker root\n"
                "        if: ${{ always() }}\n        working-directory:",
            ),
            "stage guard weakened": (
                "env.BROKER_PROJECTION != ''",
                "true",
            ),
            "cleanup guard weakened": (
                "env.BROKER_MANIFEST != ''",
                "true",
            ),
            "upload guard weakened": (
                "env.BROKER_ARTIFACT_EVIDENCE != ''",
                "true",
            ),
        }
        for name, (original, replacement) in mutations.items():
            with self.subTest(name=name):
                self.assertIn(original, self.workflow)
                mutated = self.workflow.replace(original, replacement, 1)
                self.assertNotEqual(binding_failure_errors(mutated), [])

    def test_root_invocation_is_fixed_after_unprivileged_protected_build(self) -> None:
        self.assertLess(
            self.workflow.index("Build only trusted protected-source artifacts without root"),
            self.workflow.index("Build a protected immutable OWASP CRS bundle without root"),
        )
        self.assertLess(
            self.workflow.index("Build a protected immutable OWASP CRS bundle without root"),
            self.workflow.index("Admit only verified artifacts into the root-owned broker root"),
        )
        self.assertIn("make fetch-deps", self.workflow)
        self.assertIn("prepare-fresh-crs-source.sh", self.workflow)
        self.assertIn("ci/provisioning/fetch-crs.sh", self.workflow)
        self.assertIn("prepare-crs-bundle", self.workflow)
        self.assertIn("prepare-from-snapshot", self.workflow)
        self.assertIn("sudo -- /usr/bin/python3 -I ci/runtime/broker/nginx_root_broker.py action", self.workflow)
        for action in (
            "validate-manifest",
            "config-test",
            "start",
            "verify-runtime-profile",
            "verify-master-worker-identity",
            "project-evidence",
            "stop",
            "cleanup-status",
        ):
            self.assertIn(action, self.workflow)
        for forbidden in ("sudo -E", "sudo sh -c", "sudo bash -c", "systemctl", "service "):
            self.assertNotIn(forbidden, self.workflow)
        for forbidden in ("--broker-parent", "--staging-root", "--runtime-snapshot"):
            self.assertNotIn(forbidden, self.workflow)

    def test_runtime_component_snapshot_contract_is_fixed_before_build_and_candidate_use(self) -> None:
        self.assertEqual(runtime_component_snapshot_contract_errors(self.workflow), [])
        required_snapshot_selection = (
            "          RUNTIME_COMPONENT_SNAPSHOT_CONTRACT: protected-nginx-broker"
        )
        required_rpath_selection = '          NGX_IGNORE_RPATH: "YES"'
        build_step_header = (
            "      - name: Build only trusted protected-source artifacts without root\n"
            "        working-directory:"
        )
        mutations = {
            "snapshot selector omitted": (required_snapshot_selection, ""),
            "selector accepts caller expression": (
                required_snapshot_selection,
                "          RUNTIME_COMPONENT_SNAPSHOT_CONTRACT: ${{ inputs.runtime_component_snapshot_contract }}",
            ),
            "selector duplicated outside the trusted build": (
                required_snapshot_selection,
                "\n".join((required_snapshot_selection, required_snapshot_selection)),
            ),
            "RPATH selector omitted": (required_rpath_selection, ""),
            "RPATH selector accepts caller expression": (
                required_rpath_selection,
                "          NGX_IGNORE_RPATH: ${{ inputs.ngx_ignore_rpath }}",
            ),
            "RPATH selector duplicated outside the trusted build": (
                required_rpath_selection,
                "\n".join((required_rpath_selection, required_rpath_selection)),
            ),
            "trusted build conditionally selects the contract": (
                build_step_header,
                "      - name: Build only trusted protected-source artifacts without root\n"
                "        if: ${{ github.ref == 'refs/heads/master' }}\n"
                "        working-directory:",
            ),
        }
        for name, (original, replacement) in mutations.items():
            with self.subTest(name=name):
                self.assertIn(original, self.workflow)
                mutated = self.workflow.replace(original, replacement, 1)
                self.assertNotEqual(runtime_component_snapshot_contract_errors(mutated), [])

    def test_crs_fetch_umask_is_scoped_and_restored(self) -> None:
        self.assertEqual(crs_fetch_umask_contract_errors(self.workflow), [])
        scoped_fetch = "\n".join(
            (
                "          if (",
                "            umask 022",
                '            case "$(umask)" in',
                "              022|0022) ;;",
                "              *) exit 77 ;;",
                "            esac",
                "            sh modules/ModSecurity-test-Framework/ci/provisioning/fetch-crs.sh",
                "          ); then",
            )
        )
        restore = "\n".join(
            (
                "          fi",
                '          case "$(umask)" in',
                "            077|0077) ;;",
                "            *) exit 77 ;;",
                "          esac",
                '          if [ "$fetch_status" -ne 0 ]; then',
                '            exit "$fetch_status"',
                "          fi",
            )
        )
        mutations = {
            "global 022": (scoped_fetch, "          umask 022\n" + scoped_fetch),
            "fetch outside the subshell": (
                scoped_fetch,
                "\n".join(
                    (
                        "          umask 022",
                        '          case "$(umask)" in',
                        "            022|0022) ;;",
                        "            *) exit 77 ;;",
                        "          esac",
                        "          sh modules/ModSecurity-test-Framework/ci/provisioning/fetch-crs.sh",
                    )
                ),
            ),
            "outer restoration omitted": (restore, "          fi"),
            "fetch failure accepted": ('            exit "$fetch_status"', "            true"),
            "recursive mode normalization": (
                "          . ci/runtime/lifecycle/prepare-fresh-crs-source.sh",
                "          . ci/runtime/lifecycle/prepare-fresh-crs-source.sh\n          chmod -R u=rwX,go=rX \"$CRS_SOURCE_DIR\"",
            ),
        }
        for name, (original, replacement) in mutations.items():
            with self.subTest(name=name):
                self.assertIn(original, self.workflow)
                mutated = self.workflow.replace(original, replacement, 1)
                self.assertNotEqual(crs_fetch_umask_contract_errors(mutated), [])

    def test_failed_crs_fetch_restores_outer_umask_and_fails_closed(self) -> None:
        returncode, outer_umask = run_failed_crs_fetch_umask_probe(self.workflow)
        self.assertEqual(returncode, 1)
        self.assertIn(outer_umask, {"077", "0077"})

    def run_protected_crs_tag_probe(
        self, temporary: Path, *, moved_tag: bool = False, wrong_head: bool = False,
        wrong_origin: bool = False, existing_wrong_tag: bool = False, annotated: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path, str]:
        def git(directory: Path, *arguments: str) -> str:
            return subprocess.check_output(
                ["/usr/bin/git", "-C", str(directory), *arguments], text=True,
                stderr=subprocess.PIPE,
            ).strip()

        upstream = temporary / "upstream"
        upstream.mkdir()
        git(upstream, "init")
        git(upstream, "config", "user.name", "CRS regression fixture")
        git(upstream, "config", "user.email", "crs@example.invalid")
        (upstream / "rules.conf").write_text("approved rule\n", encoding="utf-8")
        git(upstream, "add", "rules.conf")
        git(upstream, "commit", "-m", "approved CRS")
        approved_commit = git(upstream, "rev-parse", "HEAD")
        (upstream / "rules.conf").write_text("changed rule\n", encoding="utf-8")
        git(upstream, "commit", "-am", "different CRS")
        different_commit = git(upstream, "rev-parse", "HEAD")
        release_tag = "v4.29.0"
        tag_commit = different_commit if moved_tag else approved_commit
        tag_arguments = ("-a", release_tag, "-m", "reviewed release", tag_commit) if annotated else (release_tag, tag_commit)
        git(upstream, "tag", *tag_arguments)

        source = temporary / "fresh-source"
        source.mkdir()
        git(source, "init")
        git(source, "fetch", "--no-tags", str(upstream), approved_commit)
        if wrong_head or existing_wrong_tag:
            git(source, "fetch", "--no-tags", str(upstream), different_commit)
        git(source, "checkout", "--detach", different_commit if wrong_head else approved_commit)
        repository_url = "https://github.com/coreruleset/coreruleset.git"
        git(source, "remote", "add", "origin", "https://example.invalid/foreign.git" if wrong_origin else repository_url)
        self.assertEqual(git(source, "tag", "--list"), "")
        if existing_wrong_tag:
            git(source, "tag", release_tag, different_commit)

        protected = temporary / "protected"
        broker_path = protected / "ci/runtime/broker/nginx_root_broker.py"
        broker_path.parent.mkdir(parents=True)
        broker_path.write_text(
            f"CRS_APPROVED_REPOSITORY = {repository_url!r}\n"
            f"CRS_RELEASE_TAG = {release_tag!r}\n"
            f"CRS_APPROVED_COMMIT = {approved_commit!r}\n",
            encoding="utf-8",
        )
        workflow_path = protected / ".github/workflows/nginx-root-broker.yml"
        workflow_path.parent.mkdir(parents=True)
        workflow_path.write_text(self.workflow, encoding="utf-8")
        git(protected, "init")
        git(protected, "config", "user.name", "Protected broker fixture")
        git(protected, "config", "user.email", "broker@example.invalid")
        git(protected, "add", ".")
        git(protected, "commit", "-m", "protected broker constants and workflow")
        broker_sha = git(protected, "rev-parse", "HEAD")
        (protected / ".venv/bin").mkdir(parents=True)
        (protected / ".venv/bin/python").symlink_to(sys.executable)
        mock_bin = temporary / "mock-bin"
        mock_bin.mkdir()
        # Redirect only the exact protected network fetch to the local upstream;
        # all ref, origin, HEAD, and peeling checks execute actual Git commands.
        (mock_bin / "git").write_text(
            f"#!{sys.executable}\n"
            "import os, subprocess, sys\n"
            "args = sys.argv[1:]\n"
            "if 'fetch' in args:\n"
            "    expected = ['-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never', '-C', os.environ['CRS_SOURCE_DIR'], 'fetch', '--depth', '1', '--no-tags', os.environ['PROTECTED_REPOSITORY_URL'], 'refs/tags/v4.29.0:refs/tags/v4.29.0']\n"
            "    if args != expected:\n"
            "        raise SystemExit('unexpected protected CRS fetch')\n"
            "    args = [os.environ['LOCAL_UPSTREAM'] if arg == os.environ['PROTECTED_REPOSITORY_URL'] else 'protocol.file.allow=always' if arg == 'protocol.file.allow=never' else arg for arg in args]\n"
            "raise SystemExit(subprocess.run(['/usr/bin/git', *args]).returncode)\n",
            encoding="utf-8",
        )
        (mock_bin / "git").chmod(0o700)
        step = step_block(self.workflow, "Build a protected immutable OWASP CRS bundle without root")
        verification = re.search(r"(?ms)^          verify_broker_source\(\) \{\n.*?^          \}", step)
        self.assertIsNotNone(verification)
        assert verification is not None
        start = step.index("          # The broker independently acquires")
        end = step.index("          .venv/bin/python ci/runtime/broker/nginx_root_broker.py prepare-crs-bundle", start)
        admission = temporary / "bundle-admitted"
        result = subprocess.run(
            ["bash", "-c", "set -euo pipefail\n" + textwrap.dedent(verification.group(0)) + "\n" + textwrap.dedent(step[start:end]) + '\ntouch "$ADMISSION_MARKER"'],
            cwd=protected, capture_output=True, text=True, check=False,
            env={
                "LC_ALL": "C", "PATH": f"{mock_bin}:{os.defpath}", "BASH_ENV": "/dev/null",
                "BROKER_SHA": broker_sha, "CRS_SOURCE_DIR": str(source),
                "LOCAL_UPSTREAM": str(upstream), "PROTECTED_REPOSITORY_URL": repository_url,
                "ADMISSION_MARKER": str(admission),
            },
        )
        return result, admission, source, approved_commit

    def test_commit_only_crs_checkout_gains_the_exact_protected_release_tag(self) -> None:
        for annotated in (False, True):
            with self.subTest(annotated=annotated), tempfile.TemporaryDirectory() as raw:
                result, admission, source, approved_commit = self.run_protected_crs_tag_probe(Path(raw), annotated=annotated)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(admission.exists())
                peeled = subprocess.check_output(
                    ["/usr/bin/git", "-C", str(source), "rev-parse", "refs/tags/v4.29.0^{}"], text=True,
                ).strip()
                self.assertEqual(peeled, approved_commit)

    def test_wrong_crs_release_tag_or_checkout_is_rejected_before_bundle_admission(self) -> None:
        for changes in (
            {"moved_tag": True}, {"wrong_head": True}, {"wrong_origin": True},
            {"existing_wrong_tag": True},
        ):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as raw:
                result, admission, _source, _approved_commit = self.run_protected_crs_tag_probe(Path(raw), **changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(admission.exists())
                self.assertNotIn("unexpected protected CRS fetch", result.stderr)

    def test_protected_tag_provenance_is_loaded_from_verified_broker_source(self) -> None:
        step = step_block(self.workflow, "Build a protected immutable OWASP CRS bundle without root")
        before_contract = step[:step.index('          broker_crs_contract=')]
        self.assertTrue(before_contract.rstrip().endswith("# Select provenance from the blob-verified broker, never caller data."))
        self.assertIn("verify_broker_source ci/runtime/broker/nginx_root_broker.py", before_contract)
        self.assertIn('.venv/bin/python -I -c', step)
        for constant in ("CRS_APPROVED_REPOSITORY", "CRS_RELEASE_TAG", "CRS_APPROVED_COMMIT"):
            self.assertIn(f'broker["{constant}"]', step)
        self.assertNotIn("${{", step.split("        run: |", 1)[1])
        self.assertNotIn("--force", step)
        self.assertLess(step.index('refs/tags/$broker_crs_tag^{}'), step.index("prepare-crs-bundle"))

    def test_protected_build_uses_the_existing_no_rpath_opt_in(self) -> None:
        config = NGINX_CONFIG.read_text(encoding="utf-8")
        self.assertEqual(nginx_explicit_library_rpath_contract_errors(config), [])
        expected = '\n'.join(
            (
                '        if [ "$NGX_IGNORE_RPATH" = "YES" ]; then',
                '            ngx_feature_libs="-L$MODSECURITY_LIB -lmodsecurity $YAJL_EXTRA"',
                '        elif [ $NGX_RPATH = YES ]; then',
            )
        )
        mutated = config.replace(
            expected,
            '\n'.join(
                (
                    '        if [ $NGX_RPATH = YES ]; then',
                    '            ngx_feature_libs="-R$MODSECURITY_LIB -L$MODSECURITY_LIB -lmodsecurity $YAJL_EXTRA"',
                    '        elif [ "$NGX_IGNORE_RPATH" = "YES" ]; then',
                )
            ),
            1,
        )
        self.assertNotEqual(nginx_explicit_library_rpath_contract_errors(mutated), [])

    def test_bounded_evidence_is_staged_before_descriptor_cleanup_and_records_its_outcome(self) -> None:
        self.assertLess(
            self.workflow.index("Run fixed root-only NGINX actions"),
            self.workflow.index("Stage the fixed root-to-user evidence outside the cleanup root"),
        )
        self.assertLess(
            self.workflow.index("Stage the fixed root-to-user evidence outside the cleanup root"),
            self.workflow.index("Stop and verify root cleanup"),
        )
        self.assertLess(
            self.workflow.index("Stop and verify root cleanup"),
            self.workflow.index("Upload bounded root-to-user evidence"),
        )
        for filename in (
            "identity.json",
            "runtime.json",
            "policy.json",
            "nginx-access.log",
            "nginx-error.log",
            "nginx-audit.log",
            "cleanup.json",
        ):
            self.assertIn(filename, self.workflow)
        self.assertIn('"cleanup_status":"%s"', self.workflow)
        self.assertNotIn("cp -r", self.workflow)
        self.assertNotIn("tar ", self.workflow)

    def test_caller_data_is_limited_to_a_declarative_artifact_and_pinned_inputs(self) -> None:
        for field in (
            "caller_manifest_artifact",
            "parent_head_sha",
            "framework_sha",
            "protected_broker_sha",
            "matrix_variant",
            "run_id",
        ):
            self.assertIn(f"      {field}:\n", self.workflow)
        self.assertIn("Download declarative caller manifest", self.workflow)
        self.assertIn("caller-manifest.json", self.workflow)
        self.assertIn("--expected-parent-head \"$EXPECTED_PARENT_HEAD\"", self.workflow)
        self.assertIn("--expected-framework-sha \"$EXPECTED_FRAMEWORK_SHA\"", self.workflow)
        self.assertIn("--expected-run-id \"$BROKER_RUN_ID\"", self.workflow)
        self.assertIn("--expected-matrix-variant \"$BROKER_VARIANT\"", self.workflow)
        self.assertNotIn("github.event.pull_request.head.sha", self.workflow)
        self.assertNotIn("GITHUB_TOKEN", self.workflow)

    def test_actions_are_full_sha_pinned(self) -> None:
        for action in re.findall(r"uses:\s+([^\s]+)", self.workflow):
            self.assertRegex(action, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
