from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = connector_root()
RUNNER = load_source(source_path('common/scripts/run_local_runtime_smoke.py', root=ROOT))


class CommonRuntimeSmokeCrsSourceSecurityTest(unittest.TestCase):
    @staticmethod
    def make_args(
        *,
        crs_source_dir: Path | str = "",
        runtime_lookup_root: list[Path | str] | None = None,
        evidence_root: Path | None = None,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            crs_source_dir=str(crs_source_dir),
            runtime_lookup_root=[str(path) for path in runtime_lookup_root or []],
            evidence_root=str(evidence_root) if evidence_root is not None else "",
            crs_smoke_case="minimal",
            crs_git_ref="",
        )

    @staticmethod
    def make_runtime_args(
        verified_root: Path, **overrides: object
    ) -> argparse.Namespace:
        values: dict[str, object] = {
            "connector": "envoy",
            "integration_mode": "local",
            "resolved_runtime_binary": "/bin/true",
            "runtime_binary_env_var": "ENVOY_BIN",
            "runtime_binary_name": "envoy",
            "runtime_lookup_root": [],
            "evidence_root": str(verified_root / "evidence"),
            "results_dir": str(verified_root / "results"),
            "connector_root": str(ROOT),
            "source_root": str(verified_root / "src"),
            "build_root": str(verified_root / "build"),
            "tmp_root": str(verified_root / "tmp"),
            "log_root": str(verified_root / "logs"),
            "log_dir": str(verified_root / "logs/envoy"),
            "config_root": str(verified_root / "config"),
            "listen_port": 0,
            "upstream_port": 0,
            "authz_port": 0,
            "harness_path": "",
            "architecture_decision": "",
            "decision_backend": "simple",
            "modsecurity_ruleset": "targeted",
            "modsecurity_smoke_case": "targeted",
            "crs_smoke_case": "minimal",
            "modsecurity_rule_file": "",
            "modsecurity_include_dir": "",
            "modsecurity_lib_dir": "",
            "modsecurity_lib_file": "",
            "modsecurity_pkg_config_path": "",
            "modsecurity_prefix": "",
            "modsecurity_manifest": "",
            "crs_repo_url": "",
            "crs_git_ref": "",
            "crs_source_dir": "",
            "crs_runtime_dir": "",
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    @staticmethod
    def make_crs_source(path: Path) -> Path:
        path.mkdir(parents=True, mode=0o700)
        path.chmod(0o700)
        setup = path / "crs-setup.conf.example"
        setup.write_text("SecRuleEngine On\n", encoding="utf-8")
        setup.chmod(stat.S_IRUSR | stat.S_IWUSR)
        rules_dir = path / "rules"
        rules_dir.mkdir(mode=0o700)
        rules_dir.chmod(0o700)
        rule = rules_dir / "REQUEST-901-INITIALIZATION.conf"
        rule.write_text('SecRule ARGS "@contains safe" "id:901001,pass,nolog"\n', encoding="utf-8")
        rule.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return path

    def make_evaluator_inputs(self, root: Path) -> argparse.Namespace:
        include_dir = root / "include"
        header_dir = include_dir / "modsecurity"
        header_dir.mkdir(parents=True, mode=0o700)
        for header in ("modsecurity.h", "rules_set.h", "transaction.h"):
            header_path = header_dir / header
            header_path.write_text("/* test header */\n", encoding="utf-8")
            header_path.chmod(0o600)
        lib_dir = root / "lib"
        lib_dir.mkdir(mode=0o700)
        lib_file = lib_dir / "libmodsecurity.so.3"
        lib_file.write_text("test library\n", encoding="utf-8")
        lib_file.chmod(0o600)
        rule_file = root / "rules.conf"
        rule_file.write_text("SecRuleEngine On\n", encoding="utf-8")
        rule_file.chmod(0o600)
        args = self.make_runtime_args(root)
        args.modsecurity_include_dir = str(include_dir)
        args.modsecurity_lib_dir = str(lib_dir)
        args.modsecurity_lib_file = str(lib_file)
        args.modsecurity_rule_file = str(rule_file)
        args.effective_modsecurity_rule_file = str(rule_file)
        return args

    def test_evaluator_inputs_accept_private_regular_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-evaluator-input-") as temporary:
            args = self.make_evaluator_inputs(Path(temporary))

            inputs = RUNNER.prepare_modsecurity_evaluator_inputs(args)

            self.assertEqual(inputs.include_dir, Path(args.modsecurity_include_dir))
            self.assertEqual(inputs.lib_dir, Path(args.modsecurity_lib_dir))
            self.assertEqual(inputs.lib_file, Path(args.modsecurity_lib_file))
            self.assertEqual(inputs.rule_file, Path(args.modsecurity_rule_file))

    def test_evaluator_inputs_reject_linker_separator_before_compiler_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-evaluator-input-") as temporary:
            root = Path(temporary)
            args = self.make_evaluator_inputs(root)
            unsafe_dir = root / "lib,unsafe"
            Path(args.modsecurity_lib_dir).rename(unsafe_dir)
            unsafe_file = unsafe_dir / "libmodsecurity.so.3"
            args.modsecurity_lib_dir = str(unsafe_dir)
            args.modsecurity_lib_file = str(unsafe_file)

            with self.assertRaisesRegex(RUNNER.SmokeBlocked, "linker separator"):
                RUNNER.prepare_modsecurity_evaluator_inputs(args)

    def test_evaluator_inputs_reject_replaceable_library_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-evaluator-input-") as temporary:
            args = self.make_evaluator_inputs(Path(temporary))
            Path(args.modsecurity_lib_file).chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)

            with self.assertRaisesRegex(
                RUNNER.SmokeBlocked, "must not be group or world writable"
            ):
                RUNNER.prepare_modsecurity_evaluator_inputs(args)

    def test_evaluator_inputs_reject_library_outside_selected_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-evaluator-input-") as temporary:
            root = Path(temporary)
            args = self.make_evaluator_inputs(root)
            outside = root / "outside.so"
            outside.write_text("test library\n", encoding="utf-8")
            outside.chmod(0o600)
            args.modsecurity_lib_file = str(outside)

            with self.assertRaisesRegex(RUNNER.SmokeBlocked, "must be inside"):
                RUNNER.prepare_modsecurity_evaluator_inputs(args)

    def test_evaluator_build_uses_the_verified_library_file_without_shell(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-evaluator-input-") as temporary:
            root = Path(temporary)
            args = self.make_evaluator_inputs(root)
            tmp_root = root / "tmp"
            log_dir = root / "logs"
            tmp_root.mkdir(mode=0o700)
            log_dir.mkdir(mode=0o700)
            runtime_paths = RUNNER.RuntimeOutputPaths(
                root,
                root / "evidence",
                root / "results",
                tmp_root,
                root / "log-root",
                log_dir,
                root / "config",
            )
            observed: list[list[str]] = []

            def compile_once(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                observed.append(command)
                Path(command[command.index("-o") + 1]).write_text("binary\n", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            with (
                mock.patch.object(RUNNER, "system_cxx_compiler", return_value=Path("/fixed/c++")),
                mock.patch.object(RUNNER.subprocess, "run", side_effect=compile_once) as run,
            ):
                output, _environment = RUNNER.build_modsecurity_evaluator(args, runtime_paths)

            self.assertTrue(output.is_file())
            run.assert_called_once()
            self.assertEqual(observed[0][0], "/fixed/c++")
            self.assertIn(args.modsecurity_lib_file, observed[0])
            self.assertNotIn("-lmodsecurity", observed[0])
            self.assertNotIn("-L", observed[0])
            self.assertEqual(observed[0][observed[0].index("-o") + 1], str(output))

    def test_evaluator_build_rejects_unsafe_linker_input_without_process_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-evaluator-input-") as temporary:
            root = Path(temporary)
            args = self.make_evaluator_inputs(root)
            unsafe_dir = root / "lib,unsafe"
            Path(args.modsecurity_lib_dir).rename(unsafe_dir)
            args.modsecurity_lib_dir = str(unsafe_dir)
            args.modsecurity_lib_file = str(unsafe_dir / "libmodsecurity.so.3")
            runtime_paths = RUNNER.RuntimeOutputPaths(
                root,
                root / "evidence",
                root / "results",
                root / "tmp",
                root / "log-root",
                root / "logs",
                root / "config",
            )

            with mock.patch.object(RUNNER.subprocess, "run") as run:
                with self.assertRaisesRegex(RUNNER.SmokeBlocked, "linker separator"):
                    RUNNER.build_modsecurity_evaluator(args, runtime_paths)

            run.assert_not_called()

    def test_shared_temporary_environment_is_not_an_implicit_crs_candidate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            temporary_root = Path(temporary)
            self.make_crs_source(
                temporary_root / "ModSecurity-conector-verified/src/coreruleset"
            )
            args = self.make_args()
            with mock.patch.dict(
                os.environ,
                {"RUNNER_TEMP": str(temporary_root), "TMPDIR": str(temporary_root)},
                clear=False,
            ):
                self.assertEqual(RUNNER.crs_source_candidate_roots(args), [])
                with self.assertRaisesRegex(RUNNER.SmokeBlocked, "missing CRS_SOURCE_DIR"):
                    RUNNER.resolve_crs_source_dir(args)

    def test_trusted_explicit_crs_source_generates_smoke_config(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            temporary_root = Path(temporary)
            source_dir = self.make_crs_source(temporary_root / "crs-source")
            evidence_root = temporary_root / "evidence"
            evidence_root.mkdir(mode=0o700)
            evidence_root.chmod(0o700)
            (evidence_root / "crs-smoke").mkdir(mode=0o700)
            (evidence_root / "crs-smoke").chmod(0o700)
            log_dir = temporary_root / "logs"
            log_dir.mkdir(mode=0o700)
            args = self.make_args(crs_source_dir=source_dir, evidence_root=evidence_root)

            resolved = RUNNER.resolve_crs_source_dir(args)
            rule_file, runtime_dir, _version = RUNNER.prepare_crs_smoke_config(
                args, log_dir
            )

            self.assertEqual(source_dir, resolved)
            self.assertEqual(evidence_root / "crs-smoke", runtime_dir)
            self.assertIn(str(source_dir / "rules"), rule_file.read_text(encoding="utf-8"))

    def test_trusted_runtime_lookup_root_candidate_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            temporary_root = Path(temporary)
            lookup_root = temporary_root / "runtime-root"
            lookup_root.mkdir(mode=0o700)
            lookup_root.chmod(0o700)
            source_dir = self.make_crs_source(lookup_root / "sources/coreruleset")
            args = self.make_args(runtime_lookup_root=[lookup_root])

            self.assertEqual(source_dir, RUNNER.resolve_crs_source_dir(args))

    def test_symlinked_crs_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            temporary_root = Path(temporary)
            source_dir = self.make_crs_source(temporary_root / "crs-source")
            alias = temporary_root / "crs-alias"
            alias.symlink_to(source_dir, target_is_directory=True)
            args = self.make_args(crs_source_dir=alias)

            with self.assertRaisesRegex(RUNNER.SmokeBlocked, "must not contain a symlink"):
                RUNNER.resolve_crs_source_dir(args)

    def test_group_or_world_writable_rules_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            source_dir = self.make_crs_source(Path(temporary) / "crs-source")
            rules_dir = source_dir / "rules"
            rules_dir.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            args = self.make_args(crs_source_dir=source_dir)

            with self.assertRaisesRegex(RUNNER.SmokeBlocked, "must not be group or world writable"):
                RUNNER.resolve_crs_source_dir(args)

    def test_group_or_world_writable_rule_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            source_dir = self.make_crs_source(Path(temporary) / "crs-source")
            rule_file = source_dir / "rules/REQUEST-901-INITIALIZATION.conf"
            rule_file.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            args = self.make_args(crs_source_dir=source_dir)

            with self.assertRaisesRegex(RUNNER.SmokeBlocked, "must not be group or world writable"):
                RUNNER.resolve_crs_source_dir(args)

    def test_group_or_world_writable_included_plugin_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            source_dir = self.make_crs_source(Path(temporary) / "crs-source")
            plugins_dir = source_dir / "plugins"
            plugins_dir.mkdir(mode=0o700)
            plugins_dir.chmod(0o700)
            plugin_file = plugins_dir / "local-before.conf"
            plugin_file.write_text(
                'SecRule ARGS "@contains safe" "id:901002,pass,nolog"\n', encoding="utf-8"
            )
            plugin_file.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            args = self.make_args(crs_source_dir=source_dir)

            with self.assertRaisesRegex(RUNNER.SmokeBlocked, "must not be group or world writable"):
                RUNNER.resolve_crs_source_dir(args)

    def test_sticky_parent_must_also_be_trusted(self) -> None:
        sticky_parent = SimpleNamespace(
            st_mode=stat.S_IFDIR | stat.S_ISVTX | stat.S_IWGRP
        )
        runner_owned_child = SimpleNamespace(st_mode=stat.S_IFDIR | stat.S_IRWXU)

        with mock.patch.object(
            RUNNER, "is_trusted_crs_owner", side_effect=[False, True]
        ):
            self.assertFalse(
                RUNNER.crs_directory_entry_is_protected(
                    sticky_parent, runner_owned_child
                )
            )
        with mock.patch.object(
            RUNNER, "is_trusted_crs_owner", side_effect=[True, True]
        ):
            self.assertTrue(
                RUNNER.crs_directory_entry_is_protected(
                    sticky_parent, runner_owned_child
                )
            )

    def test_group_or_world_writable_evidence_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            temporary_root = Path(temporary)
            source_dir = self.make_crs_source(temporary_root / "crs-source")
            evidence_root = temporary_root / "evidence"
            evidence_root.mkdir(mode=0o700)
            evidence_root.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            log_dir = temporary_root / "logs"
            log_dir.mkdir(mode=0o700)
            args = self.make_args(crs_source_dir=source_dir, evidence_root=evidence_root)

            with self.assertRaisesRegex(
                RUNNER.SmokeBlocked,
                "CRS evidence root must not be group or world writable",
            ):
                RUNNER.prepare_crs_smoke_config(args, log_dir)

    def test_group_or_world_writable_runtime_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            temporary_root = Path(temporary)
            source_dir = self.make_crs_source(temporary_root / "crs-source")
            evidence_root = temporary_root / "evidence"
            evidence_root.mkdir(mode=0o700)
            evidence_root.chmod(0o700)
            runtime_dir = evidence_root / "crs-smoke"
            runtime_dir.mkdir(mode=0o700)
            runtime_dir.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            log_dir = temporary_root / "logs"
            log_dir.mkdir(mode=0o700)
            args = self.make_args(crs_source_dir=source_dir, evidence_root=evidence_root)

            with self.assertRaisesRegex(
                RUNNER.SmokeBlocked,
                "CRS smoke runtime directory must not be group or world writable",
            ):
                RUNNER.prepare_crs_smoke_config(args, log_dir)

    def test_symlinked_runtime_directory_is_rejected_before_generated_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            temporary_root = Path(temporary)
            source_dir = self.make_crs_source(temporary_root / "crs-source")
            evidence_root = temporary_root / "evidence"
            evidence_root.mkdir(mode=0o700)
            evidence_root.chmod(0o700)
            target_dir = temporary_root / "target"
            target_dir.mkdir(mode=0o700)
            (evidence_root / "crs-smoke").symlink_to(target_dir, target_is_directory=True)
            log_dir = temporary_root / "logs"
            log_dir.mkdir(mode=0o700)
            args = self.make_args(crs_source_dir=source_dir, evidence_root=evidence_root)

            with self.assertRaisesRegex(RUNNER.SmokeBlocked, "must not contain a symlink"):
                RUNNER.prepare_crs_smoke_config(args, log_dir)

    def test_symlinked_generated_setup_file_is_rejected_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            temporary_root = Path(temporary)
            source_dir = self.make_crs_source(temporary_root / "crs-source")
            evidence_root = temporary_root / "evidence"
            runtime_dir = evidence_root / "crs-smoke"
            runtime_dir.mkdir(parents=True, mode=0o700)
            evidence_root.chmod(0o700)
            runtime_dir.chmod(0o700)
            protected_target = temporary_root / "protected-setup"
            protected_target.write_text("keep\n", encoding="utf-8")
            protected_target.chmod(0o600)
            (runtime_dir / "crs-setup.conf").symlink_to(protected_target)
            log_dir = temporary_root / "logs"
            log_dir.mkdir(mode=0o700)
            args = self.make_args(crs_source_dir=source_dir, evidence_root=evidence_root)

            with self.assertRaisesRegex(
                RUNNER.SmokeBlocked,
                "generated CRS setup file must not contain a symlink",
            ):
                RUNNER.prepare_crs_smoke_config(args, log_dir)
            self.assertEqual(protected_target.read_text(encoding="utf-8"), "keep\n")

    def test_symlinked_generated_rule_file_is_rejected_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            temporary_root = Path(temporary)
            source_dir = self.make_crs_source(temporary_root / "crs-source")
            evidence_root = temporary_root / "evidence"
            runtime_dir = evidence_root / "crs-smoke"
            runtime_dir.mkdir(parents=True, mode=0o700)
            evidence_root.chmod(0o700)
            runtime_dir.chmod(0o700)
            protected_target = temporary_root / "protected-rule"
            protected_target.write_text("keep\n", encoding="utf-8")
            protected_target.chmod(0o600)
            (runtime_dir / "modsecurity-crs-smoke.conf").symlink_to(protected_target)
            log_dir = temporary_root / "logs"
            log_dir.mkdir(mode=0o700)
            args = self.make_args(crs_source_dir=source_dir, evidence_root=evidence_root)

            with self.assertRaisesRegex(
                RUNNER.SmokeBlocked,
                "generated CRS smoke rule must not contain a symlink",
            ):
                RUNNER.prepare_crs_smoke_config(args, log_dir)
            self.assertEqual(protected_target.read_text(encoding="utf-8"), "keep\n")

    def test_group_or_world_writable_audit_log_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            temporary_root = Path(temporary)
            source_dir = self.make_crs_source(temporary_root / "crs-source")
            evidence_root = temporary_root / "evidence"
            evidence_root.mkdir(mode=0o700)
            evidence_root.chmod(0o700)
            log_dir = temporary_root / "logs"
            log_dir.mkdir(mode=0o700)
            log_dir.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            args = self.make_args(crs_source_dir=source_dir, evidence_root=evidence_root)

            with self.assertRaisesRegex(
                RUNNER.SmokeBlocked,
                "CRS audit-log directory must not be group or world writable",
            ):
                RUNNER.prepare_crs_smoke_config(args, log_dir)

    def test_symlinked_audit_log_is_rejected_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            temporary_root = Path(temporary)
            source_dir = self.make_crs_source(temporary_root / "crs-source")
            evidence_root = temporary_root / "evidence"
            evidence_root.mkdir(mode=0o700)
            evidence_root.chmod(0o700)
            log_dir = temporary_root / "logs"
            log_dir.mkdir(mode=0o700)
            protected_target = temporary_root / "protected-audit"
            protected_target.write_text("keep\n", encoding="utf-8")
            protected_target.chmod(0o600)
            (log_dir / "crs-audit.log").symlink_to(protected_target)
            args = self.make_args(crs_source_dir=source_dir, evidence_root=evidence_root)

            with self.assertRaisesRegex(
                RUNNER.SmokeBlocked,
                "generated CRS audit log must not contain a symlink",
            ):
                RUNNER.prepare_crs_smoke_config(args, log_dir)
            self.assertEqual(protected_target.read_text(encoding="utf-8"), "keep\n")

    def test_quoted_source_path_is_rejected_before_config_generation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            temporary_root = Path(temporary)
            source_dir = self.make_crs_source(temporary_root / 'crs"source')
            evidence_root = temporary_root / "evidence"
            evidence_root.mkdir(mode=0o700)
            evidence_root.chmod(0o700)
            log_dir = temporary_root / "logs"
            log_dir.mkdir(mode=0o700)
            args = self.make_args(crs_source_dir=source_dir, evidence_root=evidence_root)

            with self.assertRaisesRegex(
                RUNNER.SmokeBlocked, "unsupported characters for a ModSecurity directive"
            ):
                RUNNER.prepare_crs_smoke_config(args, log_dir)

    def test_globbed_source_path_is_rejected_before_config_generation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-crs-source-") as temporary:
            temporary_root = Path(temporary)
            source_dir = self.make_crs_source(temporary_root / "crs*source")
            evidence_root = temporary_root / "evidence"
            evidence_root.mkdir(mode=0o700)
            evidence_root.chmod(0o700)
            log_dir = temporary_root / "logs"
            log_dir.mkdir(mode=0o700)
            args = self.make_args(crs_source_dir=source_dir, evidence_root=evidence_root)

            with self.assertRaisesRegex(
                RUNNER.SmokeBlocked, "unsupported characters for a ModSecurity directive"
            ):
                RUNNER.prepare_crs_smoke_config(args, log_dir)

    def assert_outside_runtime_output_is_rejected(self, field: str) -> None:
        with tempfile.TemporaryDirectory(prefix="common-runtime-output-") as temporary:
            temporary_root = Path(temporary)
            verified_root = temporary_root / "verified"
            outside_path = temporary_root / "outside" / field
            args = self.make_runtime_args(verified_root, **{field: str(outside_path)})
            with (
                mock.patch.dict(os.environ, {"VERIFIED_RUN_ROOT": str(verified_root)}, clear=True),
                mock.patch.object(RUNNER, "write_result") as write_result,
            ):
                self.assertEqual(RUNNER.run_smoke(args), 77)

            self.assertFalse(outside_path.exists())
            write_result.assert_not_called()

    def test_outside_runtime_config_root_is_rejected_before_runner_writes(self) -> None:
        self.assert_outside_runtime_output_is_rejected("config_root")

    def test_outside_runtime_log_dir_is_rejected_before_runner_writes(self) -> None:
        self.assert_outside_runtime_output_is_rejected("log_dir")

    def test_relative_runtime_log_dir_is_rejected_before_runner_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-runtime-output-") as temporary:
            temporary_root = Path(temporary)
            verified_root = temporary_root / "verified"
            relative_log_dir = Path("relative/log")
            args = self.make_runtime_args(verified_root, log_dir=str(relative_log_dir))
            previous_directory = Path.cwd()
            working_directory = temporary_root / "working-directory"
            working_directory.mkdir(mode=0o700)
            try:
                os.chdir(working_directory)
                with (
                    mock.patch.dict(
                        os.environ, {"VERIFIED_RUN_ROOT": str(verified_root)}, clear=True
                    ),
                    mock.patch.object(RUNNER, "write_result") as write_result,
                ):
                    self.assertEqual(RUNNER.run_smoke(args), 77)
            finally:
                os.chdir(previous_directory)

            self.assertFalse((working_directory / relative_log_dir).exists())
            write_result.assert_not_called()

    def test_broad_verified_runtime_root_is_rejected_before_runner_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-runtime-output-") as temporary:
            candidate_root = Path("/tmp") / Path(temporary).name
            args = self.make_runtime_args(candidate_root)

            with (
                mock.patch.dict(os.environ, {"VERIFIED_RUN_ROOT": "/tmp"}, clear=True),
                mock.patch.object(RUNNER, "write_result") as write_result,
            ):
                self.assertEqual(RUNNER.run_smoke(args), 77)

            self.assertFalse(candidate_root.exists())
            write_result.assert_not_called()

    def test_other_outside_runtime_output_roots_are_rejected_before_runner_writes(self) -> None:
        for field in ("evidence_root", "results_dir", "tmp_root", "log_root"):
            with self.subTest(field=field):
                self.assert_outside_runtime_output_is_rejected(field)

    def test_verified_runtime_output_paths_are_accepted_and_normalized(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-runtime-output-") as temporary:
            verified_root = Path(temporary) / "verified"
            args = self.make_runtime_args(verified_root)

            with mock.patch.dict(
                os.environ, {"VERIFIED_RUN_ROOT": str(verified_root)}, clear=True
            ):
                paths = RUNNER.validate_runtime_output_paths(args)

            self.assertEqual(paths.config_root, (verified_root / "config").resolve())
            self.assertEqual(paths.log_dir, (verified_root / "logs/envoy").resolve())
            self.assertEqual(args.results_dir, str((verified_root / "results").resolve()))

    def test_result_object_preserves_writer_evidence_arguments(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-runtime-result-") as temporary:
            verified_root = Path(temporary) / "verified"
            args = self.make_runtime_args(
                verified_root,
                decision_backend="libmodsecurity",
                modsecurity_ruleset="crs",
                modsecurity_smoke_case="targeted",
                modsecurity_rule_file="/runtime/rules.conf",
            )
            result = RUNNER.SmokeResult(
                "BLOCKED",
                77,
                False,
                200,
                403,
                skipped_reason="missing libmodsecurity",
                missing=("libmodsecurity",),
                modsecurity_backend_verified=True,
                modsecurity_rule_loaded=True,
                intervention_status=403,
                decision_log_path="/runtime/decision.log",
                audit_log_path="/runtime/audit.log",
                request_body_smoke_verified=True,
                request_body_access_enabled=True,
                request_body_rule_loaded=True,
                crs_minimal_smoke_verified=True,
                crs_rule_id="942100",
                crs_rule_message="SQLi",
            )

            command = RUNNER.writer_args(args, result)

        values = dict(zip(command[::2], command[1::2], strict=True))
        self.assertEqual(values["--status"], "BLOCKED")
        self.assertEqual(values["--exit-code"], "77")
        self.assertEqual(values["--allowed-request-status"], "200")
        self.assertEqual(values["--blocked-request-status"], "403")
        self.assertEqual(values["--modsecurity-rule-file"], "/runtime/rules.conf")
        self.assertEqual(values["--modsecurity-rule-id"], "942100")
        self.assertEqual(values["--request-body-smoke-verified"], "true")
        self.assertEqual(values["--intervention-status"], "403")
        self.assertEqual(values["--audit-log-path"], "/runtime/audit.log")
        self.assertEqual(values["--decision-log-path"], "/runtime/decision.log")
        self.assertEqual(values["--crs-minimal-smoke-verified"], "true")
        self.assertEqual(values["--crs-rule-message"], "SQLi")
        self.assertEqual(values["--skipped-reason"], "missing libmodsecurity")
        self.assertIn("--missing-dependency", command)
        self.assertEqual(command[command.index("--missing-dependency") + 1], "libmodsecurity")

    def test_smoke_result_keeps_backend_evidence_and_paths_separate(self) -> None:
        evidence = RUNNER.BackendEvidence(
            modsecurity_backend_verified=True,
            modsecurity_rule_loaded=True,
            intervention_status=403,
            request_body_smoke_verified=True,
            crs_minimal_smoke_verified=True,
            crs_rule_id="942100",
            crs_rule_message="SQLi",
        )

        result = RUNNER.smoke_result(
            "BLOCKED",
            77,
            False,
            200,
            403,
            evidence,
            skipped_reason="missing libmodsecurity",
            missing=("libmodsecurity",),
            context={
                "decision_log_path": "/runtime/decision.log",
                "audit_log_path": "/runtime/audit.log",
            },
        )

        self.assertTrue(result.modsecurity_backend_verified)
        self.assertTrue(result.modsecurity_rule_loaded)
        self.assertEqual(result.intervention_status, 403)
        self.assertTrue(result.request_body_smoke_verified)
        self.assertTrue(result.crs_minimal_smoke_verified)
        self.assertEqual(result.crs_rule_id, "942100")
        self.assertEqual(result.decision_log_path, "/runtime/decision.log")
        self.assertEqual(result.audit_log_path, "/runtime/audit.log")

    def test_writer_values_preserve_crs_case_when_backend_is_simple(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-runtime-writer-") as temporary:
            args = self.make_runtime_args(
                Path(temporary),
                decision_backend="simple",
                modsecurity_ruleset="crs",
                crs_smoke_case="secondary",
            )
            values = RUNNER.smoke_writer_values(
                args, RUNNER.SmokeResult("BLOCKED", 77, False, None, None)
            )

        self.assertEqual(values.modsecurity_ruleset, "")
        self.assertEqual(values.modsecurity_smoke_case, "")
        self.assertEqual(values.crs_smoke_case, "secondary")

    def test_symlinked_runtime_output_path_is_rejected_before_runner_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-runtime-output-") as temporary:
            temporary_root = Path(temporary)
            verified_root = temporary_root / "verified"
            verified_root.mkdir(mode=0o700)
            outside_root = temporary_root / "outside"
            outside_root.mkdir(mode=0o700)
            output_alias = verified_root / "output-alias"
            output_alias.symlink_to(outside_root, target_is_directory=True)
            args = self.make_runtime_args(
                verified_root, config_root=str(output_alias / "config")
            )

            with mock.patch.dict(
                os.environ, {"VERIFIED_RUN_ROOT": str(verified_root)}, clear=True
            ):
                with self.assertRaisesRegex(
                    RUNNER.SmokeBlocked, "CONFIG_ROOT must not contain a symlink"
                ):
                    RUNNER.validate_runtime_output_paths(args)

            self.assertFalse((outside_root / "config").exists())

    def test_symlink_loop_runtime_output_path_is_blocked_before_runner_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-runtime-output-") as temporary:
            temporary_root = Path(temporary)
            verified_root = temporary_root / "verified"
            verified_root.mkdir(mode=0o700)
            loop = verified_root / "loop"
            loop.symlink_to("loop")
            args = self.make_runtime_args(verified_root, config_root=str(loop / "config"))

            with (
                mock.patch.dict(
                    os.environ, {"VERIFIED_RUN_ROOT": str(verified_root)}, clear=True
                ),
                mock.patch.object(RUNNER, "write_result") as write_result,
            ):
                self.assertEqual(RUNNER.run_smoke(args), 77)

            write_result.assert_not_called()

    def test_crs_config_suffix_symlink_is_blocked_before_runner_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="common-runtime-output-") as temporary:
            temporary_root = Path(temporary)
            verified_root = temporary_root / "verified"
            config_root = verified_root / "config"
            config_root.mkdir(parents=True, mode=0o700)
            outside_root = temporary_root / "outside"
            outside_root.mkdir(mode=0o700)
            (config_root / "crs-smoke").symlink_to(outside_root, target_is_directory=True)
            args = self.make_runtime_args(
                verified_root,
                config_root=str(config_root),
                decision_backend="simple",
                modsecurity_ruleset="crs",
            )

            with (
                mock.patch.dict(
                    os.environ, {"VERIFIED_RUN_ROOT": str(verified_root)}, clear=True
                ),
                mock.patch.object(RUNNER, "write_result") as write_result,
            ):
                self.assertEqual(RUNNER.run_smoke(args), 77)

            self.assertEqual(list(outside_root.iterdir()), [])
            write_result.assert_not_called()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
