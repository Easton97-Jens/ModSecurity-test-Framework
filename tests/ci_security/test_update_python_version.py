from __future__ import annotations

import importlib.util
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
    spec = importlib.util.spec_from_file_location("python_version_updater", UPDATER_PATH)
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
        "name": f"Python 3.13.{patch}",
        "slug": f"python-313{patch}",
        "is_published": True,
        "pre_release": False,
        "release_date": "2026-06-10T16:00:00Z",
    }
    record.update(overrides)
    return record


def response_for(records: list[dict[str, object]]) -> FakeResponse:
    return FakeResponse(UPDATER.json.dumps(records).encode("utf-8"))


class UpdatePythonVersionTest(unittest.TestCase):
    def make_root(self, directory: Path, version: str = "3.13.14\n") -> Path:
        root = directory / "framework"
        root.mkdir()
        (root / ".python-version").write_text(version, encoding="utf-8")
        return root

    def test_check_resolves_update_without_mutating_the_canonical_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            opener = lambda _request, _timeout: response_for(
                [stable_record(14), stable_record(15)]
            )
            result = UPDATER.resolve_update(root, opener=opener)

            self.assertEqual(result.status, "update_available")
            self.assertEqual(result.current, "3.13.14")
            self.assertEqual(result.candidate, "3.13.15")
            self.assertEqual((root / ".python-version").read_text(encoding="utf-8"), "3.13.14\n")

    def test_equal_downgrade_and_missing_stable_results_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            self.assertEqual(
                UPDATER.resolve_update(
                    root, opener=lambda _request, _timeout: response_for([stable_record(14)])
                ).status,
                "current",
            )
            self.assertEqual(
                UPDATER.resolve_update(
                    root, opener=lambda _request, _timeout: response_for([stable_record(13)])
                ).status,
                "downgrade_detected",
            )
            self.assertEqual(
                UPDATER.resolve_update(
                    root,
                    opener=lambda _request, _timeout: response_for(
                        [
                            {
                                "name": "Python 3.13.15rc1",
                                "slug": "python-31315rc1",
                                "is_published": True,
                                "pre_release": True,
                                "release_date": "2026-06-10T16:00:00Z",
                            }
                        ]
                    ),
                ).status,
                "no_stable_3_13_release",
            )

    def test_invalid_current_version_and_metadata_schema_do_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory), "3.13.014\n")
            result = UPDATER.resolve_update(
                root, opener=lambda _request, _timeout: response_for([stable_record(15)])
            )
            self.assertEqual(result.status, "invalid_current_version")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            result = UPDATER.resolve_update(
                root,
                opener=lambda _request, _timeout: response_for(
                    [stable_record(15, slug="unexpected-slug")]
                ),
            )
            self.assertEqual(result.status, "unsupported_response")
            self.assertEqual((root / ".python-version").read_text(encoding="utf-8"), "3.13.14\n")

    def test_redirect_network_failure_and_leading_zero_metadata_are_rejected(self) -> None:
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

            self.assertEqual(UPDATER.resolve_update(root, opener=blocked).status, "blocked_network")
            leading_zero = {
                "name": "Python 3.13.015",
                "slug": "python-313015",
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

    def test_update_is_atomic_and_confined_to_the_regular_canonical_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_root(Path(temporary_directory))
            unrelated = root / "unrelated.txt"
            unrelated.write_text("unchanged\n", encoding="utf-8")
            UPDATER.atomic_write_canonical_version(
                root, UPDATER.PythonVersion(14), UPDATER.PythonVersion(15)
            )
            self.assertEqual((root / ".python-version").read_text(encoding="utf-8"), "3.13.15\n")
            self.assertEqual(unrelated.read_text(encoding="utf-8"), "unchanged\n")

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            outside = directory / "outside-version"
            outside.write_text("3.13.14\n", encoding="utf-8")
            root = directory / "framework"
            root.mkdir()
            (root / ".python-version").symlink_to(outside)
            with self.assertRaisesRegex(UPDATER.UpdaterFailure, "non-symlink"):
                UPDATER.atomic_write_canonical_version(
                    root, UPDATER.PythonVersion(14), UPDATER.PythonVersion(15)
                )
            self.assertEqual(outside.read_text(encoding="utf-8"), "3.13.14\n")

    def test_expected_candidate_and_runner_outputs_are_constrained(self) -> None:
        result = UPDATER.UpdateResult(
            "update_available", "3.13.14", "3.13.15", "fixture candidate"
        )
        self.assertEqual(
            UPDATER.require_expected_candidate(result, "3.13.16").status,
            "blocked_metadata",
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            runner_temp = directory / "runner-temp"
            runner_temp.mkdir()
            output = runner_temp / "output"
            output.write_text("", encoding="ascii")
            candidate_file = runner_temp / "candidate"
            with patch.dict(
                os.environ,
                {"RUNNER_TEMP": str(runner_temp), "GITHUB_OUTPUT": str(output)},
                clear=False,
            ):
                UPDATER.write_github_outputs(result)
                UPDATER.write_candidate_file(UPDATER.PythonVersion(15), candidate_file)
                with self.assertRaisesRegex(UPDATER.UpdaterFailure, "strict child"):
                    UPDATER.write_candidate_file(
                        UPDATER.PythonVersion(15), directory / "outside"
                    )
            self.assertIn("update_available=true", output.read_text(encoding="ascii"))
            self.assertEqual(candidate_file.read_text(encoding="ascii"), "3.13.15\n")


if __name__ == "__main__":
    unittest.main()
