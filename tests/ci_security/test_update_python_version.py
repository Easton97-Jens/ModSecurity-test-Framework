from __future__ import annotations

import contextlib
from email.message import Message
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib import error


ROOT = Path(__file__).resolve().parents[2]
UPDATER_PATH = ROOT / "ci/tools/update-python-version.py"


def load_updater():
    spec = importlib.util.spec_from_file_location(
        "python_version_updater", UPDATER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {UPDATER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


UPDATER = load_updater()


class FakeResponse:
    def __init__(
        self,
        payload: bytes,
        *,
        status: int = 200,
        url: str | None = None,
        content_type: str = "application/json",
    ) -> None:
        self.payload = payload
        self.status = status
        self.url = url or UPDATER.METADATA_URL
        self.headers = {"Content-Type": content_type}
        self.closed = False

    def geturl(self) -> str:
        return self.url

    def read(self, amount: int = -1) -> bytes:
        return self.payload if amount < 0 else self.payload[:amount]

    def close(self) -> None:
        self.closed = True


def stable_record(patch: int, **overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "name": f"Python 3.14.{patch}",
        "slug": f"python-314{patch}",
        "is_published": True,
        "pre_release": False,
        "release_date": "2026-06-10T16:00:00Z",
    }
    record.update(overrides)
    return record


def response_for(records: list[dict[str, object]]) -> FakeResponse:
    return FakeResponse(UPDATER.json.dumps(records).encode("utf-8"))


class UpdatePythonVersionTest(unittest.TestCase):
    def make_root(self, directory: Path, version: str = "3.14.6\n") -> Path:
        root = directory / "framework"
        root.mkdir()
        (root / ".python-version").write_text(version, encoding="utf-8")
        return root

    def test_check_resolves_update_without_mutating_the_canonical_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))

            def opener(_request: object, _timeout: float) -> FakeResponse:
                return response_for([stable_record(6), stable_record(7)])

            result = UPDATER.resolve_update(root, opener=opener)

            self.assertEqual(result.status, "update_available")
            self.assertEqual(result.current, "3.14.6")
            self.assertEqual(result.candidate, "3.14.7")
            self.assertEqual(
                (root / ".python-version").read_text(encoding="utf-8"), "3.14.6\n"
            )

    def test_equal_downgrade_and_missing_stable_results_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            self.assertEqual(
                UPDATER.resolve_update(
                    root,
                    opener=lambda _request, _timeout: response_for([stable_record(6)]),
                ).status,
                "current",
            )
            self.assertEqual(
                UPDATER.resolve_update(
                    root,
                    opener=lambda _request, _timeout: response_for([stable_record(5)]),
                ).status,
                "downgrade_detected",
            )
            self.assertEqual(
                UPDATER.resolve_update(
                    root,
                    opener=lambda _request, _timeout: response_for(
                        [
                            {
                                "name": "Python 3.14.7rc1",
                                "slug": "python-3147rc1",
                                "is_published": True,
                                "pre_release": True,
                                "release_date": "2026-06-10T16:00:00Z",
                            }
                        ]
                    ),
                ).status,
                "no_stable_3_14_release",
            )

    def test_invalid_current_version_and_metadata_schema_do_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory), "3.14.06\n")
            result = UPDATER.resolve_update(
                root,
                opener=lambda _request, _timeout: response_for([stable_record(7)]),
            )
            self.assertEqual(result.status, "invalid_current_version")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            result = UPDATER.resolve_update(
                root,
                opener=lambda _request, _timeout: response_for(
                    [stable_record(7, slug="unexpected-slug")]
                ),
            )
            self.assertEqual(result.status, "unsupported_response")
            self.assertEqual(
                (root / ".python-version").read_text(encoding="utf-8"), "3.14.6\n"
            )

    def test_redirect_network_failure_and_leading_zero_metadata_are_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            redirected = FakeResponse(b"[]", url="https://example.invalid/releases")
            self.assertEqual(
                UPDATER.resolve_update(
                    root, opener=lambda _request, _timeout: redirected
                ).status,
                "blocked_metadata",
            )

            def blocked(_request, _timeout):
                raise error.URLError("offline")

            self.assertEqual(
                UPDATER.resolve_update(root, opener=blocked).status, "blocked_network"
            )
            leading_zero = {
                "name": "Python 3.14.07",
                "slug": "python-31407",
                "is_published": True,
                "pre_release": False,
                "release_date": "2026-06-10T16:00:00Z",
            }
            self.assertEqual(
                UPDATER.resolve_update(
                    root, opener=lambda _request, _timeout: response_for([leading_zero])
                ).status,
                "unsupported_response",
            )

    def test_ascii_only_version_and_metadata_values_are_enforced(self) -> None:
        with self.assertRaisesRegex(UPDATER.UpdaterFailure, "exact stable"):
            UPDATER.PythonVersion.parse("3.14.1\u0665")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            non_ascii_name = stable_record(
                7, name="Python 3.14.1\u0665", slug="python-3147"
            )
            self.assertEqual(
                UPDATER.resolve_update(
                    root,
                    opener=lambda _request, _timeout: response_for([non_ascii_name]),
                ).status,
                "no_stable_3_14_release",
            )
            non_ascii_date = stable_record(7, release_date="2026-06-1\u0660T16:00:00Z")
            self.assertEqual(
                UPDATER.resolve_update(
                    root,
                    opener=lambda _request, _timeout: response_for([non_ascii_date]),
                ).status,
                "unsupported_response",
            )

    def test_network_error_classification_preserves_http_ordering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))

            def timeout(_request: object, _timeout: float) -> FakeResponse:
                raise TimeoutError("fixture timeout")

            def unavailable(_request: object, _timeout: float) -> FakeResponse:
                raise OSError("fixture unavailable")

            headers: Message[str, str] = Message()
            not_found_error = error.HTTPError(
                UPDATER.METADATA_URL, 404, "not found", headers, None
            )
            self.addCleanup(not_found_error.close)

            def not_found(_request: object, _timeout: float) -> FakeResponse:
                raise not_found_error

            self.assertEqual(
                UPDATER.resolve_update(root, opener=timeout).status, "blocked_network"
            )
            self.assertEqual(
                UPDATER.resolve_update(root, opener=unavailable).status,
                "blocked_network",
            )
            self.assertEqual(
                UPDATER.resolve_update(root, opener=not_found).status,
                "blocked_metadata",
            )

    def test_unrelated_release_records_are_ignored_before_flag_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            unrelated_record: dict[str, object] = {
                "name": "Python 3.13.0",
                "is_published": "not a boolean",
                "pre_release": "not a boolean",
            }
            self.assertEqual(
                UPDATER.resolve_update(
                    root,
                    opener=lambda _request, _timeout: response_for(
                        [unrelated_record, stable_record(7)]
                    ),
                ).status,
                "update_available",
            )

    def test_update_is_atomic_and_confined_to_the_regular_canonical_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            unrelated = root / "unrelated.txt"
            unrelated.write_text("unchanged\n", encoding="utf-8")
            UPDATER.atomic_write_canonical_version(
                root, UPDATER.PythonVersion(6), UPDATER.PythonVersion(7)
            )
            self.assertEqual(
                (root / ".python-version").read_text(encoding="utf-8"), "3.14.7\n"
            )
            self.assertEqual(unrelated.read_text(encoding="utf-8"), "unchanged\n")

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            outside = directory / "outside-version"
            outside.write_text("3.14.6\n", encoding="utf-8")
            root = directory / "framework"
            root.mkdir()
            (root / ".python-version").symlink_to(outside)
            expected = UPDATER.PythonVersion(6)
            candidate = UPDATER.PythonVersion(7)
            with self.assertRaisesRegex(UPDATER.UpdaterFailure, "non-symlink"):
                UPDATER.atomic_write_canonical_version(root, expected, candidate)
            self.assertEqual(outside.read_text(encoding="utf-8"), "3.14.6\n")

    def test_expected_candidate_and_runner_outputs_are_constrained(self) -> None:
        result = UPDATER.UpdateResult(
            "update_available", "3.14.6", "3.14.7", "fixture candidate"
        )
        self.assertEqual(
            UPDATER.require_expected_candidate(result, "3.14.8").status,
            "blocked_metadata",
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            runner_temp = directory / "runner-temp"
            runner_temp.mkdir()
            output = runner_temp / "output"
            output.write_text("", encoding="ascii")
            candidate_file = runner_temp / UPDATER.CANDIDATE_FILE_NAME
            with patch.dict(
                os.environ,
                {"RUNNER_TEMP": str(runner_temp), "GITHUB_OUTPUT": str(output)},
                clear=False,
            ):
                UPDATER.write_github_outputs(result)
                UPDATER.write_candidate_file(UPDATER.PythonVersion(7))
            self.assertIn("update_available=true", output.read_text(encoding="ascii"))
            self.assertEqual(candidate_file.read_text(encoding="ascii"), "3.14.7\n")

    def test_runner_output_paths_remain_confined_and_regular(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner_temp = Path(temporary_directory) / "runner-temp"
            runner_temp.mkdir()
            missing = runner_temp / "missing-output"
            regular = runner_temp / "regular-output"
            regular.write_text("", encoding="ascii")
            directory = runner_temp / "output-directory"
            directory.mkdir()
            symlink = runner_temp / "output-symlink"
            symlink.symlink_to(regular)
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                self.assertEqual(
                    UPDATER.runner_temp_child(missing, allow_existing=True), missing
                )
                for unsafe_path in (regular, directory, symlink):
                    with self.assertRaisesRegex(UPDATER.UpdaterFailure, "safe regular"):
                        UPDATER.runner_temp_child(unsafe_path, allow_existing=False)

    def test_main_propagates_requested_write_failures_as_blocked_results(self) -> None:
        args = UPDATER.argparse.Namespace(
            check=True,
            update=False,
            expected_candidate=None,
            write_candidate_file=True,
            write_github_output=False,
            json=True,
            timeout=UPDATER.DEFAULT_TIMEOUT_SECONDS,
        )
        result = UPDATER.UpdateResult(
            "update_available", "3.14.6", "3.14.7", "fixture candidate"
        )
        output = io.StringIO()
        with (
            patch.object(UPDATER, "parse_args", return_value=args),
            patch.object(UPDATER, "resolve_update", return_value=result),
            patch.object(
                UPDATER,
                "write_candidate_file",
                side_effect=UPDATER.UpdaterFailure(
                    "blocked_metadata", "fixture candidate write failed"
                ),
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(UPDATER.main(), 2)
        rendered = UPDATER.json.loads(output.getvalue())
        self.assertEqual(rendered["status"], "blocked_metadata")
        self.assertEqual(rendered["message"], "fixture candidate write failed")

    def test_candidate_file_cli_rejects_a_caller_selected_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            outside = Path(temporary_directory) / "outside"
            with patch.object(
                sys,
                "argv",
                [
                    str(UPDATER_PATH),
                    "--check",
                    "--write-candidate-file",
                    str(outside),
                ],
            ):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        UPDATER.parse_args()


if __name__ == "__main__":
    unittest.main()
