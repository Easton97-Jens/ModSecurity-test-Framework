"""Offline Sonar credential-confinement and native-scope boundary tests."""

from copy import deepcopy
from contextlib import chdir
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load("sonar_workflow_checker", "ci/checks/security/check-github-actions-workflows.py")
NATIVE = load("sonar_native", "ci/checks/analysis/prepare-sonar-cfamily.py")


def valid_document():
    return CHECKER.yaml.safe_load((ROOT / ".github/workflows/sonarqube.yml").read_text())


class SonarScopeTests(unittest.TestCase):
    def test_root_git_metadata_is_excluded_without_hiding_product_directories(self):
        properties = dict(
            line.split("=", 1)
            for line in (ROOT / "sonar-project.properties").read_text().splitlines()
            if line and not line.startswith("#")
        )
        self.assertEqual(properties["sonar.sources"], ".")
        self.assertEqual(properties["sonar.tests"], ".")
        self.assertEqual(properties["sonar.scm.exclusions.disabled"], "true")
        expected = {".git/**", "tools/MRTS/**", "reports/**"}
        self.assertEqual(set(properties["sonar.exclusions"].split(",")), expected)
        self.assertEqual(set(properties["sonar.test.exclusions"].split(",")), expected)


class SonarSecretBoundaryTests(unittest.TestCase):
    def test_full_checker_rejects_source_revision_bypasses(self):
        original = CHECKER.yaml.safe_load((ROOT / ".github/workflows/sonarqube.yml").read_text())
        mutations = []
        document = deepcopy(original)
        document["defaults"]["run"]["shell"] = "bash -c 'git checkout master; bash \"$1\"' -- {0}"
        mutations.append(("workflow shell replaces source", document))
        for variable in ("BASH_ENV", "PATH"):
            document = deepcopy(original)
            document["env"] = {variable: "/unreviewed/bootstrap"}
            mutations.append((f"workflow environment {variable}", document))
        document = deepcopy(original)
        checkout = deepcopy(document["jobs"]["sonarqube"]["steps"][0])
        checkout["with"]["ref"] = "master"
        document["jobs"]["sonarqube"]["steps"].insert(1, checkout)
        mutations.append(("second pinned checkout", document))
        document = deepcopy(original)
        document["jobs"]["sonarqube"]["steps"].insert(1, {"name": "Replace source", "run": "git checkout master"})
        mutations.append(("inserted source replacement", document))
        document = deepcopy(original)
        document["jobs"]["sonarqube"]["steps"][2]["run"] += "\ngit checkout master\n"
        mutations.append(("modified reviewed run body", document))
        document = deepcopy(original)
        document["jobs"]["sonarqube"]["steps"][3]["env"] = {"PATH": "/unreviewed/bin"}
        mutations.append(("extra compiler step environment", document))
        document = deepcopy(original)
        document["jobs"]["sonarqube"]["steps"][3]["run"] = document["jobs"]["sonarqube"]["steps"][3]["run"].replace("prepare-sonar-cfamily.py", "unreviewed-wrapper.py")
        mutations.append(("changed compiler wrapper", document))
        document = deepcopy(original)
        document["jobs"]["sonarqube"]["steps"][3]["run"] = document["jobs"]["sonarqube"]["steps"][3]["run"].replace("prepare-sonar-sdk.sh", "unreviewed-sdk.sh")
        mutations.append(("changed approved SDK producer", document))
        for name, document in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "sonarqube.yml"
                serialized = CHECKER.yaml.safe_dump(document, sort_keys=False)
                if name == "workflow shell replaces source":
                    serialized = "\n".join(
                        "    shell: |\n      " + document["defaults"]["run"]["shell"]
                        if line.startswith("    shell:") else line
                        for line in serialized.splitlines()) + "\n"
                path.write_text("\n".join(
                    line + " # v7.0.1" if "uses: actions/checkout@" in line else
                    line + " # v7.0.0" if "uses: actions/setup-python@" in line else
                    line + " # v8.3.0" if "uses: SonarSource/" in line else line
                    for line in serialized.splitlines()) + "\n")
                with chdir(temporary):
                    self.assertEqual(CHECKER.validate_pins(path), [])
                    self.assertTrue(CHECKER.validate_permissions(path, document))

    def test_full_checker_accepts_real_workflow(self):
        path = ROOT / ".github/workflows/sonarqube.yml"
        document = CHECKER.yaml.safe_load(path.read_text())
        self.assertEqual(CHECKER.validate_pins(path), [])
        self.assertEqual(CHECKER.validate_permissions(path, document), [])

    def test_canonical_action_update_requires_matching_source_and_lock(self):
        document = valid_document()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in ("ci/lib/common.sh", "ci/tooling/security-tools.lock.yml", "ci/tools/sync-canonical-workflow-pins.py"):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            common = root / "ci/lib/common.sh"
            original = document["jobs"]["sonarqube"]["steps"][-1]["uses"].split("@")[1]
            common.write_text(common.read_text().replace(original, "a" * 40))
            with patch.object(CHECKER, "__file__", str(root / "ci/checks/security/check-github-actions-workflows.py")):
                self.assertFalse(CHECKER.sonar_pr_secret_allowed(Path("sonarqube.yml"), document))
                spec = importlib.util.spec_from_file_location("updated_canonical", root / "ci/tools/sync-canonical-workflow-pins.py")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                values = module.source_common(root)
                (root / "ci/tooling/security-tools.lock.yml").write_bytes(module.lock_values(root, values))
                document["jobs"]["sonarqube"]["steps"][-1]["uses"] = "SonarSource/sonarqube-scan-action@" + "a" * 40
                self.assertTrue(CHECKER.sonar_pr_secret_allowed(Path("sonarqube.yml"), document))

    def test_reviewed_same_repository_scanner_is_allowed(self):
        self.assertEqual(CHECKER.validate_workflow_trust_boundary(
            Path("sonarqube.yml"), valid_document(), True), [])

    def test_mutated_trust_boundaries_are_rejected(self):
        cases = []
        for guard in (None, "true", "github.event_name == 'pull_request'"):
            document = valid_document()
            document["jobs"]["sonarqube"]["if"] = guard
            cases.append((f"guard {guard}", document))
        for name, value in (("persist-credentials", True), ("submodules", True), ("ref", "master")):
            document = valid_document()
            document["jobs"]["sonarqube"]["steps"][0]["with"][name] = value
            cases.append((name, document))
        for location in ("env", "defaults", "timeout-minutes"):
            document = valid_document()
            document["jobs"]["sonarqube"][location] = "${{ secrets.SONAR_TOKEN }}"
            cases.append((location, document))
        for section in ("on", "permissions"):
            document = valid_document()
            document[section] = ({"pull_request_target": None} if section == "on"
                                 else {"contents": "write"})
            cases.append((section, document))
        for name, value in (("uses", "SonarSource/sonarqube-scan-action@v8"),
                            ("run", "printenv"), ("if", "always()"),
                            ("name", "${{ secrets.SONAR_TOKEN }}")):
            document = valid_document()
            document["jobs"]["sonarqube"]["steps"][-1][name] = value
            cases.append((name, document))
        document = valid_document()
        document["jobs"]["sonarqube"]["steps"].insert(1, {
            "run": "printenv", "env": {"TOKEN": "${{ secrets.SONAR_TOKEN }}"}})
        cases.append(("token reuse", document))
        document = valid_document()
        document["jobs"]["sonarqube"]["steps"][-1]["with"]["args"] += " -Dsonar.exclusions=**"
        cases.append(("argument injection", document))
        document = valid_document()
        document["jobs"]["other"] = deepcopy(document["jobs"]["sonarqube"])
        cases.append(("other job", document))
        for name, document in cases:
            with self.subTest(name=name):
                self.assertTrue(CHECKER.validate_workflow_trust_boundary(
                    Path("sonarqube.yml"), document, True))

    def test_exception_does_not_apply_to_other_workflows(self):
        self.assertTrue(CHECKER.validate_workflow_trust_boundary(
            Path("other.yml"), valid_document(), True))


class NativeAnalysisBoundaryTests(unittest.TestCase):
    def test_native_build_sdk_layout_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            sdk = Path(temporary)
            (sdk / "headers/modsecurity").mkdir(parents=True)
            (sdk / "src/.libs").mkdir(parents=True)
            (sdk / "headers/modsecurity/modsecurity.h").touch()
            (sdk / "src/.libs/libmodsecurity.so").touch()
            self.assertEqual(NATIVE.sdk_layout(sdk), (sdk / "headers", sdk / "src/.libs"))

    def test_mixed_sdk_layout_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            sdk = Path(temporary)
            (sdk / "include/modsecurity").mkdir(parents=True)
            (sdk / "src/.libs").mkdir(parents=True)
            (sdk / "include/modsecurity/modsecurity.h").touch()
            (sdk / "src/.libs/libmodsecurity.so").touch()
            with self.assertRaisesRegex(ValueError, "SDK requires"):
                NATIVE.sdk_layout(sdk)

    def test_preseeded_sdk_directory_symlinks_preserve_external_sentinel(self):
        for nested in (False, True):
            with self.subTest(nested=nested), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                sdk = base / "sdk"
                (sdk / "include/modsecurity").mkdir(parents=True)
                (sdk / "lib").mkdir()
                (sdk / "include/modsecurity/modsecurity.h").touch()
                (sdk / "lib/libmodsecurity.so").touch()
                output = base / "output"
                output.mkdir()
                sentinel = base / "sentinel"
                sentinel.mkdir()
                if nested:
                    (output / "sdk").mkdir()
                    (output / "sdk/src").symlink_to(sentinel, target_is_directory=True)
                else:
                    (sentinel / "src").mkdir()
                    (output / "sdk").symlink_to(sentinel, target_is_directory=True)
                before = sorted(str(path.relative_to(sentinel)) for path in sentinel.rglob("*"))
                with patch.object(NATIVE.subprocess, "run", side_effect=AssertionError("must reject before compile")):
                    with self.assertRaisesRegex(ValueError, "symlinked SDK staging directory"):
                        NATIVE.prepare(ROOT, output, sdk, "gcc")
                self.assertEqual(sorted(str(path.relative_to(sentinel)) for path in sentinel.rglob("*")), before)

    def test_preseeded_output_symlink_preserves_external_sentinel(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            sdk = base / "sdk"
            (sdk / "include/modsecurity").mkdir(parents=True)
            (sdk / "lib").mkdir()
            (sdk / "include/modsecurity/modsecurity.h").touch()
            (sdk / "lib/libmodsecurity.so").touch()
            output = base / "output"
            output.mkdir()
            sentinel = base / "sentinel"
            sentinel.write_text("preserve")
            (output / "capture-compiler").symlink_to(sentinel)
            with self.assertRaisesRegex(ValueError, "symlinked analysis output file"):
                NATIVE.prepare(ROOT, output, sdk, "gcc")
            self.assertEqual(sentinel.read_text(), "preserve")

    def test_failed_real_compile_cannot_leave_success_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            fragment = Path(temporary) / "command.json"
            fragment.write_text("stale successful record")
            with patch.object(NATIVE.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["gcc"])):
                with self.assertRaises(subprocess.CalledProcessError):
                    NATIVE.record_compile(fragment, "/usr/bin/gcc", ["-c", "file.c"])
            self.assertFalse(fragment.exists())

    def test_successful_real_compile_preserves_exact_argv(self):
        arguments = ["-std=c99", "-Wall", "-Wextra", "-Werror", "-I/sdk/headers", "-c", "file.c", "-o", "file.o"]
        with tempfile.TemporaryDirectory() as temporary:
            fragment = Path(temporary) / "command.json"
            with patch.object(NATIVE.subprocess, "run") as compiler:
                NATIVE.record_compile(fragment, "/usr/bin/gcc", arguments)
            compiler.assert_called_once_with(["/usr/bin/gcc", *arguments], check=True)
            self.assertEqual(json.loads(fragment.read_text()), {
                "directory": str(Path.cwd()), "file": "file.c",
                "arguments": ["/usr/bin/gcc", *arguments]})

    def test_checkout_output_is_rejected_before_compile(self):
        with self.assertRaisesRegex(ValueError, "outside the checkout"):
            NATIVE.prepare(ROOT, ROOT / "analysis-output", ROOT, "clang")

    def test_absent_sdk_is_rejected_before_compile(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with self.assertRaisesRegex(ValueError, "SDK requires"):
                NATIVE.prepare(ROOT, output, output / "missing-sdk", "clang")


class ApprovedSdkPreparationTests(unittest.TestCase):
    def fixture(self, base):
        root, runner = base / "framework", base / "runner"
        runner.mkdir()
        (root / "tests").mkdir(parents=True)
        (root / "Makefile").touch()
        for relative in ("ci/checks/analysis/prepare-sonar-sdk.sh", "ci/lib/path-bootstrap.sh",
                         "ci/lib/path.sh", "ci/lib/common.sh"):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        # Preserve real parent admission/creation functions. Replace only the
        # network provisioner and native build with bounded sequence witnesses.
        common = root / "ci/lib/common.sh"
        with common.open("a") as stream:
            stream.write('''\nci_provision_approved_modsecurity_v3_checkout() {
    if [ ! -d "${1%/*}" ]; then
        printf '%s\\n' 'missing source parent' >&2
        return 77
    fi
    : > "$VERIFIED_RUN_ROOT/provision-called"
}
''')
        builder = root / "ci/provisioning/build-v3-under-src.sh"
        builder.parent.mkdir(parents=True)
        builder.write_text('''#!/bin/sh
set -eu
test -f "$VERIFIED_RUN_ROOT/provision-called"
: > "$VERIFIED_RUN_ROOT/build-called"
''')
        return root, runner

    def run_helper(self, root, runner):
        return subprocess.run(
            ["sh", str(root / "ci/checks/analysis/prepare-sonar-sdk.sh")],
            env={"PATH": os.environ["PATH"], "RUNNER_TEMP": str(runner)},
            capture_output=True, text=True, check=False)

    def test_fresh_private_source_parent_precedes_provisioning(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, runner = self.fixture(Path(temporary))
            result = self.run_helper(root, runner)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            run = runner / "framework-sonar-sdk"
            self.assertTrue((run / "build-called").is_file())
            self.assertEqual(run.stat().st_mode & 0o777, 0o700)
            self.assertEqual((run / "src").stat().st_mode & 0o777, 0o700)

    def test_existing_sdk_run_root_is_rejected_before_provisioning(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, runner = self.fixture(Path(temporary))
            run = runner / "framework-sonar-sdk"
            (run / "src").mkdir(parents=True)
            result = self.run_helper(root, runner)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((run / "provision-called").exists())

    def test_symlinked_sdk_run_root_preserves_external_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, runner = self.fixture(base)
            sentinel = base / "sentinel"
            (sentinel / "src").mkdir(parents=True)
            (runner / "framework-sonar-sdk").symlink_to(sentinel, target_is_directory=True)
            result = self.run_helper(root, runner)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((sentinel / "provision-called").exists())
            self.assertEqual(list(sentinel.iterdir()), [sentinel / "src"])


if __name__ == "__main__":
    unittest.main()
