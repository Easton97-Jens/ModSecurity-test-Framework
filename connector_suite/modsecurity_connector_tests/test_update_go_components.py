from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock
from types import SimpleNamespace
from pathlib import Path

from modsecurity_connector_tests.version_updater_test_support import load_updater


SCRIPT = connector_root() / "scripts" / "update-go-components.py"
updater = load_updater("update_go_components", SCRIPT)

BASELINE_SYS = "v0.46.0"
BASELINE_NET = "v0.56.0"
BASELINE_TEXT = "v0.39.0"
TARGET_SYS = "v0.49.0"
TARGET_NET = "v0.61.0"
TARGET_TEXT = "v0.43.0"
# Stable fixture versions above every approved floor; these are not latest pins.
NEWER_BUNDLE = {
    "grpc_version": "v1.84.0",
    "sys_version": "v0.50.0",
    "net_version": "v0.62.0",
    "text_version": "v0.44.0",
}


def go_mod(
    grpc_version: str,
    *,
    sys_version: str = BASELINE_SYS,
    net_version: str = BASELINE_NET,
    text_version: str = BASELINE_TEXT,
) -> str:
    return f"""module github.com/Easton97-Jens/ModSecurity-conector/connectors/envoy/ext_proc

go 1.26.5

require (
\tgithub.com/envoyproxy/go-control-plane/envoy v1.37.0
\tgolang.org/x/sys {sys_version}
\tgoogle.golang.org/grpc {grpc_version}
\tgoogle.golang.org/protobuf v1.36.11
)

require (
\tgolang.org/x/net {net_version} // indirect
\tgolang.org/x/text {text_version} // indirect
)
"""


def checksum_entries(
    grpc_version: str,
    *,
    sys_version: str,
    net_version: str,
    text_version: str,
) -> str:
    return "".join(
        f"{module} {version}{suffix} {checksum_for(module, version, suffix, token)}\n"
        for module, version, token in (
            ("golang.org/x/net", net_version, "net"),
            ("golang.org/x/sys", sys_version, "sys"),
            ("golang.org/x/text", text_version, "text"),
            ("google.golang.org/grpc", grpc_version, "grpc"),
        )
        for suffix in ("", "/go.mod")
    )


def checksum_for(module: str, version: str, suffix: str, token: str) -> str:
    return updater.TRUSTED_TARGET_GO_SUM_ENTRIES.get(
        (module, version, suffix),
        f"h1:{token}=",
    )


def baseline_go_sum(*, extra: str = "") -> str:
    return (
        "github.com/envoyproxy/go-control-plane/envoy v1.37.0 h1:envoy=\n"
        "google.golang.org/protobuf v1.36.11 h1:protobuf=\n"
        + checksum_entries(
            "v1.83.1",
            sys_version=BASELINE_SYS,
            net_version=BASELINE_NET,
            text_version=BASELINE_TEXT,
        )
        + extra
    )


def candidate_go_sum(
    grpc_version: str = "v1.83.2",
    *,
    sys_version: str = TARGET_SYS,
    net_version: str = TARGET_NET,
    text_version: str = TARGET_TEXT,
    extra: str = "",
) -> str:
    return (
        baseline_go_sum()
        + checksum_entries(
            grpc_version,
            sys_version=sys_version,
            net_version=net_version,
            text_version=text_version,
        )
        + extra
    )


def target_go_mod(grpc_version: str = "v1.83.2") -> str:
    return go_mod(
        grpc_version,
        sys_version=TARGET_SYS,
        net_version=TARGET_NET,
        text_version=TARGET_TEXT,
    )


class UpdateGoComponentsTests(unittest.TestCase):
    def test_cli_root_accepts_only_actual_canonical_repository(self):
        trusted = updater.repository_root()
        arguments = SimpleNamespace(repository_root=str(trusted))
        self.assertEqual(updater._select_repository_root(arguments, None), trusted)

    def test_copied_script_cli_default_selects_its_private_source_tree(self):
        # Copy/import the real scripts without executing any component action.
        # Private-copy frames keep their actual filenames; no coverage relabeling.
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            scripts = private / "scripts"
            scripts.mkdir()
            for name in ("update-go-components.py", "version_updater_common.py"):
                original = (SCRIPT.parent / name).read_bytes()
                copied = scripts / name
                copied.write_bytes(original)
                self.assertEqual(copied.read_bytes(), original)
            copied = scripts / "update-go-components.py"
            spec = importlib.util.spec_from_file_location("private_component_cli", copied)
            module = importlib.util.module_from_spec(spec)
            previous_path = list(sys.path)
            try:
                with mock.patch.dict(sys.modules):
                    sys.modules.pop("version_updater_common", None)
                    sys.modules[spec.name] = module
                    spec.loader.exec_module(module)
                    arguments = module.build_arg_parser().parse_args(["--check"])
                    self.assertEqual(module._select_repository_root(arguments, None), private)
                    self.assertEqual(module._select_repository_root.__code__.co_filename, str(copied))
                    self.assertEqual(Path(sys.modules["version_updater_common"].__file__), scripts / "version_updater_common.py")
            finally:
                sys.path[:] = previous_path

    def test_cli_root_rejects_sibling_before_component_actions(self):
        trusted = updater.repository_root()
        sibling = str(trusted.parent / (trusted.name + "-foreign"))
        output = io.StringIO()
        with mock.patch.object(updater, "apply_component_requirements") as apply:
            status = updater.main(["--apply-requirements", "--repository-root", sibling, "--json"], output=output)
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "error")
        apply.assert_not_called()

    def test_cli_root_rejects_traversal_alias(self):
        trusted = updater.repository_root()
        arguments = SimpleNamespace(repository_root=str(trusted) + "/../" + trusted.name)
        with self.assertRaisesRegex(updater.ComponentError, "canonical source repository"):
            updater._select_repository_root(arguments, None)

    def test_cli_root_rejects_symlink_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            alias = Path(directory) / "repository-alias"
            alias.symlink_to(updater.repository_root(), target_is_directory=True)
            arguments = SimpleNamespace(repository_root=str(alias))
            with self.assertRaisesRegex(updater.ComponentError, "canonical source repository"):
                updater._select_repository_root(arguments, None)

    def test_injected_library_root_remains_separate_from_cli_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            arguments = SimpleNamespace(repository_root="/foreign-untrusted-cli")
            self.assertEqual(updater._select_repository_root(arguments, private), private)

    def root_with_module(
        self,
        root: Path,
        *,
        go_mod_source: str | None = None,
        go_sum_source: str | None = None,
    ) -> Path:
        module = root / "connectors" / "envoy" / "ext_proc"
        module.mkdir(parents=True)
        (module / "go.mod").write_text(go_mod_source or go_mod("v1.83.1"), encoding="utf-8")
        (module / "go.sum").write_text(go_sum_source or baseline_go_sum(), encoding="utf-8")
        return root

    def run_cli(
        self,
        root: Path,
        argv: list[str],
        *,
        baseline_frame: bytes = b"",
    ) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        status = updater.main(
            argv,
            root=root,
            output=output,
            input_stream=io.BytesIO(baseline_frame),
        )
        return status, json.loads(output.getvalue())

    @staticmethod
    def baseline_frame() -> bytes:
        return (
            go_mod("v1.83.1").encode("utf-8")
            + updater.BASELINE_FRAME_SEPARATOR
            + baseline_go_sum().encode("utf-8")
        )

    @staticmethod
    def resolve_workflow(
        component_report: dict[str, object], go_report: dict[str, object],
    ) -> subprocess.CompletedProcess[str]:
        workflow = (SCRIPT.parents[1] / ".github/workflows/update-go-version.yml").read_text()
        prefix = 'GO_REPORT="$go_report" COMPONENT_REPORT="$component_report" python3 - <<\'PY\' >> "$GITHUB_OUTPUT"\n'
        source = textwrap.dedent(workflow.split(prefix, 1)[1].split("          PY\n", 1)[0])
        return subprocess.run(
            [sys.executable, "-c", source], check=False, capture_output=True, text=True,
            env={**os.environ, "GO_REPORT": json.dumps(go_report), "COMPONENT_REPORT": json.dumps(component_report)},
        )

    def test_resolves_the_only_approved_component_floor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_with_module(Path(temporary))
            status, result = self.run_cli(root, ["--check", "--json"])
        self.assertEqual(status, 0)
        self.assertEqual(result["status"], "update_available")
        self.assertIs(result["update_available"], True)
        self.assertEqual(
            result["components"],
            [
                {
                    "directory": "connectors/envoy/ext_proc",
                    "dependency": "google.golang.org/grpc",
                    "current_version": "v1.83.1",
                    "target_version": "v1.83.2",
                    "update_available": True,
                    "requirements": [
                        {
                            "dependency": update.dependency,
                            "current_version": str(update.baseline_version),
                            "target_version": str(update.target_version),
                            "update_available": True,
                        }
                        for update in updater.GRPC_COMPONENT.updates
                    ],
                }
            ],
        )

    def test_current_or_newer_complete_bundle_needs_no_component_update(self) -> None:
        for version in ("v1.83.2", "v1.83.10", "v1.84.0", "v1.100.0"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                root = self.root_with_module(Path(temporary), go_mod_source=target_go_mod(version))
                status, result = self.run_cli(root, ["--check", "--json"])
            self.assertEqual(status, 0)
            self.assertEqual(result["status"], "current")
            self.assertIs(result["update_available"], False)

    def test_newer_dependency_bundle_is_current_without_rewriting_files(self) -> None:
        source = go_mod(**NEWER_BUNDLE)
        sums = checksum_entries(**NEWER_BUNDLE)
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_with_module(Path(temporary), go_mod_source=source, go_sum_source=sums)
            module = root / updater.GRPC_COMPONENT.directory
            before = {name: (module / name).read_bytes() for name in ("go.mod", "go.sum")}
            status, report = self.run_cli(root, ["--check", "--json"])
            self.assertEqual((status, report["status"], report["update_available"]), (0, "current", False))
            self.assertTrue(all(not row["update_available"] for row in report["components"][0]["requirements"]))
            status, result = self.run_cli(root, ["--apply-requirements", "--json"])
            self.assertEqual((status, result["status"]), (0, "current"))
            self.assertEqual({name: (module / name).read_bytes() for name in before}, before)

    def test_mixed_floor_bundle_preserves_newer_requirements_and_trusted_checksums(self) -> None:
        versions = {**NEWER_BUNDLE, "sys_version": TARGET_SYS, "net_version": "v0.58.0"}
        source = go_mod(**versions)
        baseline_sums = checksum_entries(**versions)
        expected = go_mod(**{**versions, "net_version": TARGET_NET})
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_with_module(Path(temporary), go_mod_source=source, go_sum_source=baseline_sums)
            status, report = self.run_cli(root, ["--check", "--json"])
            self.assertEqual((status, report["status"]), (0, "update_available"))
            pending = [row["dependency"] for row in report["components"][0]["requirements"] if row["update_available"]]
            self.assertEqual(pending, [updater.NET_MODULE])
            status, result = self.run_cli(root, ["--apply-requirements", "--json"])
            self.assertEqual((status, result["status"]), (0, "updated"))
            module = root / updater.GRPC_COMPONENT.directory
            self.assertEqual((module / "go.mod").read_text(), expected)
            self.assertEqual((module / "go.sum").read_text(), baseline_sums)
        floor_sums = "".join(
            f"{updater.NET_MODULE} {TARGET_NET}{suffix} {checksum_for(updater.NET_MODULE, TARGET_NET, suffix, 'net')}\n"
            for suffix in ("", "/go.mod")
        )
        result = updater.validate_component_candidate(
            source.encode(), expected.encode(), baseline_sums.encode(), (baseline_sums + floor_sums).encode(),
        )
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["go_mod_sha256"], hashlib.sha256(expected.encode()).hexdigest())

    def test_candidate_rejects_downgrading_a_newer_dependency_to_its_floor(self) -> None:
        versions = {**NEWER_BUNDLE, "net_version": "v0.58.0"}
        baseline = go_mod(**versions)
        downgraded = go_mod(**{**versions, "grpc_version": "v1.83.2", "net_version": TARGET_NET})
        candidate_inputs = (
            baseline.encode(), downgraded.encode(),
            checksum_entries(**versions).encode(), candidate_go_sum().encode(),
        )
        with self.assertRaisesRegex(updater.ComponentError, "outside the approved bundle"):
            updater.validate_component_candidate(*candidate_inputs)

    def test_workflow_resolver_accepts_newer_and_mixed_floor_bundles(self) -> None:
        cases = (
            ("newer", NEWER_BUNDLE, True, False),
            ("mixed", {**NEWER_BUNDLE, "net_version": "v0.58.0"}, False, True),
        )
        for name, versions, toolchain_update, component_update in cases:
            with self.subTest(bundle=name), tempfile.TemporaryDirectory() as temporary:
                root = self.root_with_module(Path(temporary), go_mod_source=go_mod(**versions))
                report = updater.resolution_payload(updater.resolve_component(root))
                go_report = {
                    "current_version": "1.27.2",
                    "latest_version": "1.27.3" if toolchain_update else "1.27.2",
                    "status": "update_available" if toolchain_update else "current",
                    "update_available": toolchain_update,
                }
                result = self.resolve_workflow(report, go_report)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"toolchain_update_available={str(toolchain_update).lower()}\n", result.stdout)
                self.assertIn(f"component_update_available={str(component_update).lower()}\n", result.stdout)
                self.assertIn("update_available=true\n", result.stdout)

    def test_rejects_malformed_unregistered_or_missing_requirements(self) -> None:
        cases = {
            "prerelease": go_mod("v1.83.2-rc.1"),
            "indirect": go_mod("v1.83.1").replace(
                "\tgoogle.golang.org/grpc v1.83.1\n",
                "\tgoogle.golang.org/grpc v1.83.1 // indirect\n",
            ),
            "missing": go_mod("v1.83.1").replace("\tgoogle.golang.org/grpc v1.83.1\n", ""),
            "unregistered_net": go_mod("v1.83.1", net_version="v0.57.0"),
            "unregistered_sys": go_mod("v1.83.2", sys_version="v0.45.0"),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = self.root_with_module(Path(temporary), go_mod_source=source)
                status, result = self.run_cli(root, ["--check", "--json"])
            self.assertEqual((status, result["status"]), (1, "error"))

    def test_registered_security_updates_do_not_require_a_grpc_upgrade(self) -> None:
        for grpc_version in ("v1.83.1", "v1.83.2", "v1.84.0"):
            with self.subTest(grpc_version=grpc_version), tempfile.TemporaryDirectory() as temporary:
                source = go_mod(grpc_version, sys_version=TARGET_SYS, text_version=TARGET_TEXT)
                root = self.root_with_module(Path(temporary), go_mod_source=source)
                status, result = self.run_cli(root, ["--check", "--json"])
                self.assertEqual((status, result["status"]), (0, "update_available"))
                status, result = self.run_cli(root, ["--apply-requirements", "--json"])
                self.assertEqual((status, result["status"]), (0, "updated"))
                expected = target_go_mod("v1.83.2" if grpc_version == "v1.83.1" else grpc_version)
                self.assertEqual((root / updater.GRPC_COMPONENT.directory / "go.mod").read_text(), expected)
                status, result = self.run_cli(root, ["--apply-requirements", "--json"])
                self.assertEqual((status, result["status"]), (0, "current"))

    def test_requirement_writer_rejects_unregistered_versions_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_with_module(Path(temporary), go_mod_source=go_mod("v1.83.1", net_version="v0.57.0"))
            path = root / updater.GRPC_COMPONENT.directory / "go.mod"
            before = path.read_bytes()
            status, result = self.run_cli(root, ["--apply-requirements", "--json"])
            self.assertEqual((status, result["status"]), (1, "error"))
            self.assertEqual(path.read_bytes(), before)
            path.unlink()
            outside = root / "outside"
            outside.write_text(go_mod("v1.83.1"))
            path.symlink_to(outside)
            status, result = self.run_cli(root, ["--apply-requirements", "--json"])
            self.assertEqual((status, result["status"]), (1, "error"))
            self.assertEqual(outside.read_text(), go_mod("v1.83.1"))

    def test_previous_registered_bundle_updates_with_unchanged_safe_grpc(self) -> None:
        baseline_mod = go_mod("v1.83.2", sys_version="v0.47.0", net_version="v0.58.0", text_version="v0.41.0")
        baseline_sum = checksum_entries("v1.83.2", sys_version="v0.47.0", net_version="v0.58.0", text_version="v0.41.0")
        target_sum = checksum_entries("v1.83.2", sys_version=TARGET_SYS, net_version=TARGET_NET, text_version=TARGET_TEXT)
        result = updater.validate_component_candidate(
            baseline_mod.encode(), target_go_mod().encode(), baseline_sum.encode(), target_sum.encode(),
        )
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["baseline_version"], result["target_version"])
        for update in updater.GRPC_COMPONENT.updates:
            with self.subTest(dependency=update.dependency):
                key = (update.dependency, str(update.target_version), "")
                bad_sum = target_sum.replace(updater.TRUSTED_TARGET_GO_SUM_ENTRIES[key], "h1:tampered=")
                candidate_inputs = (
                    baseline_mod.encode(), target_go_mod().encode(), baseline_sum.encode(), bad_sum.encode(),
                )
                with self.assertRaises(updater.ComponentError):
                    updater.validate_component_candidate(*candidate_inputs)

    def test_workflow_resolver_accepts_component_only_updates_and_rejects_corrupt_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_with_module(Path(temporary), go_mod_source=go_mod("v1.83.2"))
            report = updater.resolution_payload(updater.resolve_component(root))
        go_report = {"current_version": "1.27.2", "latest_version": "1.27.2", "status": "current", "update_available": False}

        result = self.resolve_workflow(report, go_report)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("toolchain_update_available=false\n", result.stdout)
        self.assertIn("component_update_available=true\n", result.stdout)
        self.assertIn("update_available=true\n", result.stdout)
        for failure in ("false_floor", "unapproved_target", "duplicate", "non_string"):
            with self.subTest(failure=failure):
                bad = json.loads(json.dumps(report))
                requirements = bad["components"][0]["requirements"]
                if failure == "false_floor":
                    requirements[-1]["update_available"] = False
                elif failure == "unapproved_target":
                    requirements[-1]["target_version"] = "v0.99.0"
                elif failure == "duplicate":
                    requirements[-1] = requirements[0]
                else:
                    requirements[-1]["current_version"] = 43
                result = self.resolve_workflow(bad, go_report)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_component_requirements_rejects_nested_require_blocks(self) -> None:
        source = go_mod("v1.83.1").replace(
            "\tgoogle.golang.org/grpc v1.83.1\n",
            "require (\n\tgoogle.golang.org/grpc v1.83.1\n",
        )
        with self.assertRaisesRegex(updater.ComponentError, r"go\.mod contains nested require blocks"):
            updater.component_requirements(source, updater.GRPC_COMPONENT)

    def test_component_requirements_rejects_unterminated_require_blocks(self) -> None:
        source = go_mod("v1.83.1").removesuffix(")\n")
        with self.assertRaisesRegex(updater.ComponentError, r"go\.mod has an unterminated require block"):
            updater.component_requirements(source, updater.GRPC_COMPONENT)

    def test_component_requirements_rejects_duplicate_component_requirements(self) -> None:
        requirement = "\tgoogle.golang.org/grpc v1.83.1\n"
        source = go_mod("v1.83.1").replace(requirement, requirement * 2)
        with self.assertRaisesRegex(
            updater.ComponentError,
            r"go\.mod contains duplicate google\.golang\.org/grpc requirements",
        ):
            updater.component_requirements(source, updater.GRPC_COMPONENT)

    def test_rejects_a_symlinked_component_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "connectors" / "envoy" / "ext_proc"
            module.mkdir(parents=True)
            outside = root / "outside-go-mod"
            outside.write_text(go_mod("v1.83.1"), encoding="utf-8")
            (module / "go.mod").symlink_to(outside)
            (module / "go.sum").write_text(baseline_go_sum(), encoding="utf-8")
            status, result = self.run_cli(root, ["--check", "--json"])
        self.assertEqual((status, result["status"]), (1, "error"))

    def test_rejects_a_symlinked_component_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside_module = root / "outside" / "envoy" / "ext_proc"
            outside_module.mkdir(parents=True)
            (outside_module / "go.mod").write_text(go_mod("v1.83.1"), encoding="utf-8")
            (outside_module / "go.sum").write_text(baseline_go_sum(), encoding="utf-8")
            (root / "connectors").symlink_to(root / "outside", target_is_directory=True)
            status, result = self.run_cli(root, ["--check", "--json"])
        self.assertEqual((status, result["status"]), (1, "error"))

    def test_preflight_rejects_symlinks_without_modifying_their_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            for filename, source in (("go.mod", go_mod("v1.83.1")), ("go.sum", baseline_go_sum())):
                with self.subTest(filename=filename):
                    root = self.root_with_module(temporary_path / filename)
                    module = root / "connectors" / "envoy" / "ext_proc"
                    target = root / f"outside-{filename}"
                    target.write_text(source, encoding="utf-8")
                    (module / filename).unlink()
                    (module / filename).symlink_to(target)
                    before = target.read_bytes()
                    status, result = self.run_cli(root, ["--validate-component-files", "--json"])
                    self.assertEqual((status, result["status"]), (1, "error"))
                    self.assertEqual(target.read_bytes(), before)

            root = temporary_path / "intermediate-directory"
            outside_module = root / "outside" / "envoy" / "ext_proc"
            outside_module.mkdir(parents=True)
            target_go_mod = outside_module / "go.mod"
            target_go_sum = outside_module / "go.sum"
            target_go_mod.write_text(go_mod("v1.83.1"), encoding="utf-8")
            target_go_sum.write_text(baseline_go_sum(), encoding="utf-8")
            before_go_mod = target_go_mod.read_bytes()
            before_go_sum = target_go_sum.read_bytes()
            (root / "connectors").symlink_to(root / "outside", target_is_directory=True)
            status, result = self.run_cli(root, ["--validate-component-files", "--json"])
            self.assertEqual((status, result["status"]), (1, "error"))
            self.assertEqual(target_go_mod.read_bytes(), before_go_mod)
            self.assertEqual(target_go_sum.read_bytes(), before_go_sum)

    def test_preflight_accepts_real_component_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_with_module(Path(temporary))
            status, result = self.run_cli(root, ["--validate-component-files", "--json"])
        self.assertEqual(status, 0)
        self.assertEqual(
            result,
            {
                "status": "valid",
                "directory": "connectors/envoy/ext_proc",
                "files": ["go.mod", "go.sum"],
            },
        )

    def test_preflight_rejects_hardlinked_component_inputs(self) -> None:
        for filename in ("go.mod", "go.sum"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = self.root_with_module(Path(temporary))
                source = root / updater.GRPC_COMPONENT.directory / filename
                alias = root / f"outside-{filename}"
                os.link(source, alias)
                before = alias.read_bytes()
                status, result = self.run_cli(root, ["--apply-requirements", "--json"])
                self.assertEqual((status, result["status"]), (1, "error"))
                self.assertEqual(alias.read_bytes(), before)

    def test_candidate_cli_reads_only_static_component_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_with_module(
                Path(temporary),
                go_mod_source=target_go_mod(),
                go_sum_source=candidate_go_sum(),
            )
            status, result = self.run_cli(
                root,
                ["--validate-candidate", "--json"],
                baseline_frame=self.baseline_frame(),
            )
        self.assertEqual(status, 0)
        self.assertEqual(result["status"], "valid")

    def test_candidate_cli_rejects_malformed_baseline_frames_and_symlinked_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root_with_module(
                Path(temporary),
                go_mod_source=target_go_mod(),
                go_sum_source=candidate_go_sum(),
            )
            malformed_frames = {
                "no_separator": self.baseline_frame().replace(updater.BASELINE_FRAME_SEPARATOR, b"", 1),
                "extra_separator": self.baseline_frame() + updater.BASELINE_FRAME_SEPARATOR,
                "oversized": b"x" * (updater.MAX_BASELINE_FRAME_BYTES + 1),
            }
            for name, baseline_frame in malformed_frames.items():
                with self.subTest(name=name):
                    status, result = self.run_cli(
                        root,
                        ["--validate-candidate", "--json"],
                        baseline_frame=baseline_frame,
                    )
                    self.assertEqual((status, result["status"]), (1, "error"))

            module = root / "connectors" / "envoy" / "ext_proc"
            outside = root / "outside-go-mod"
            outside.write_text(target_go_mod(), encoding="utf-8")
            (module / "go.mod").unlink()
            (module / "go.mod").symlink_to(outside)
            before = outside.read_bytes()
            status, result = self.run_cli(
                root,
                ["--validate-candidate", "--json"],
                baseline_frame=self.baseline_frame(),
            )
            self.assertEqual((status, result["status"]), (1, "error"))
            self.assertEqual(outside.read_bytes(), before)

    def test_candidate_validation_accepts_only_the_fixed_bundle_and_checksums(self) -> None:
        baseline_mod = go_mod("v1.83.1").encode("utf-8")
        candidate_mod = target_go_mod().encode("utf-8")
        baseline_sum = baseline_go_sum().encode("utf-8")
        candidate_sum = candidate_go_sum().encode("utf-8")

        result = updater.validate_component_candidate(
            baseline_mod,
            candidate_mod,
            baseline_sum,
            candidate_sum,
        )

        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["baseline_version"], "v1.83.1")
        self.assertEqual(result["target_version"], "v1.83.2")
        self.assertEqual(result["go_mod_sha256"], hashlib.sha256(candidate_mod).hexdigest())
        self.assertEqual(result["go_sum_sha256"], hashlib.sha256(candidate_sum).hexdigest())
        updater.require_expected_candidate_hashes(
            result,
            expected_go_mod_sha256=hashlib.sha256(candidate_mod).hexdigest(),
            expected_go_sum_sha256=hashlib.sha256(candidate_sum).hexdigest(),
        )
        for expected_go_mod_sha256, expected_go_sum_sha256 in (
            ("0" * 64, hashlib.sha256(candidate_sum).hexdigest()),
            ("not-a-digest", hashlib.sha256(candidate_sum).hexdigest()),
            (hashlib.sha256(candidate_mod).hexdigest(), "not-a-digest"),
        ):
            with self.subTest(
                expected_go_mod_sha256=expected_go_mod_sha256,
                expected_go_sum_sha256=expected_go_sum_sha256,
            ):
                with self.assertRaises(updater.ComponentError):
                    updater.require_expected_candidate_hashes(
                        result,
                        expected_go_mod_sha256=expected_go_mod_sha256,
                        expected_go_sum_sha256=expected_go_sum_sha256,
                    )

        tidied_candidate_sum = (
            baseline_go_sum().replace(
                checksum_entries(
                    "v1.83.1",
                    sys_version=BASELINE_SYS,
                    net_version=BASELINE_NET,
                    text_version=BASELINE_TEXT,
                ),
                "",
            )
            + checksum_entries(
                "v1.83.2",
                sys_version=TARGET_SYS,
                net_version=TARGET_NET,
                text_version=TARGET_TEXT,
            )
        ).encode("utf-8")
        self.assertEqual(
            updater.validate_component_candidate(
                baseline_mod,
                candidate_mod,
                baseline_sum,
                tidied_candidate_sum,
            )["status"],
            "valid",
        )

    def test_candidate_validation_rejects_unapproved_manifest_or_checksum_changes(self) -> None:
        baseline_mod = go_mod("v1.83.1").encode("utf-8")
        baseline_sum = baseline_go_sum().encode("utf-8")
        cases = {
            "other_direct_requirement": (
                target_go_mod().replace(
                    "\tgoogle.golang.org/protobuf v1.36.11\n",
                    "\tgoogle.golang.org/protobuf v1.36.12\n",
                ).encode("utf-8"),
                candidate_go_sum().encode("utf-8"),
            ),
            "unrelated_checksum": (
                target_go_mod().encode("utf-8"),
                candidate_go_sum(extra="golang.org/x/crypto v0.56.1 h1:crypto=\n").encode("utf-8"),
            ),
            "altered_target_checksum": (
                target_go_mod().encode("utf-8"),
                candidate_go_sum()
                .replace(
                    "h1:EManeRomTObA0BU7I8vXgg/78uE5MJ9M8B39EX2WscU=",
                    "h1:tampered=",
                )
                .encode("utf-8"),
            ),
            "wrong_target": (
                target_go_mod("v1.83.3").encode("utf-8"),
                candidate_go_sum("v1.83.3").encode("utf-8"),
            ),
        }
        for name, (candidate_mod, candidate_sum) in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(updater.ComponentError):
                    updater.validate_component_candidate(
                        baseline_mod,
                        candidate_mod,
                        baseline_sum,
                        candidate_sum,
                    )

    def test_candidate_validation_rejects_non_update_unapproved_or_missing_target_checksums(self) -> None:
        baseline_mod = go_mod("v1.83.1").encode("utf-8")
        baseline_sum = baseline_go_sum().encode("utf-8")
        target_mod = target_go_mod().encode("utf-8")
        target_sum = candidate_go_sum().encode("utf-8")
        missing_text_target_sum = (
            candidate_go_sum()
            .replace(
                f"golang.org/x/text {TARGET_TEXT} "
                f"{checksum_for('golang.org/x/text', TARGET_TEXT, '', 'text')}\n"
                f"golang.org/x/text {TARGET_TEXT}/go.mod "
                f"{checksum_for('golang.org/x/text', TARGET_TEXT, '/go.mod', 'text')}\n",
                "",
            )
            .encode("utf-8")
        )
        missing_protobuf_target_sum = (
            candidate_go_sum()
            .replace("google.golang.org/protobuf v1.36.11 h1:protobuf=\n", "")
            .encode("utf-8")
        )
        with self.assertRaises(updater.ComponentError):
            updater.validate_component_candidate(target_mod, target_mod, target_sum, target_sum)
        with self.assertRaises(updater.ComponentError):
            updater.validate_component_candidate(
                baseline_mod,
                target_mod,
                baseline_sum,
                missing_text_target_sum,
            )
        with self.assertRaises(updater.ComponentError):
            updater.validate_component_candidate(
                baseline_mod,
                target_mod,
                baseline_sum,
                missing_protobuf_target_sum,
            )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
