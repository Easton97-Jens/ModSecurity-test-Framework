"""Offline security contracts for the protected exact-head dispatcher."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import importlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = connector_root()
MODULE_PATH = source_path('ci/runtime/broker/protected_nginx_exact_head_dispatcher.py', root=ROOT)
SHA = "a" * 40
BASE = "b" * 40


def load_module() -> object:
    return importlib.import_module('modsecurity_connector_ci.runtime.broker.protected_nginx_exact_head_dispatcher')


D = load_module()


class Response:
    def __init__(self, raw: bytes, headers: dict[str, str] | None = None,
                 final_url: str | None = None) -> None:
        self.raw = raw
        self.headers = headers or {}
        self.final_url = final_url or D.API_ROOT + "354"

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, _: int) -> bytes:
        return self.raw

    def geturl(self) -> str:
        return self.final_url


class Opener:
    def __init__(self, response: Response) -> None:
        self.response = response
        self.request = None

    def open(self, request: object, timeout: int) -> Response:
        self.request = request
        return self.response


def pr_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "number": 354,
        "state": "open",
        "merged": False,
        "merged_at": None,
        "draft": True,
        "base": {"ref": "master", "sha": BASE,
                 "repo": {"full_name": D.CANONICAL_REPOSITORY}},
        "head": {"ref": "review", "sha": SHA,
                 "repo": {"full_name": D.CANONICAL_REPOSITORY}},
    }
    payload.update(overrides)
    return payload


class DispatcherTest(unittest.TestCase):
    def fetch(self, raw: bytes, headers: dict[str, str] | None = None) -> object:
        opener = Opener(Response(raw, headers))
        with mock.patch.object(D, "build_opener", return_value=opener):
            return D.fetch_pr(354)

    def test_valid_control_uses_fixed_https_get(self) -> None:
        opener = Opener(Response(json.dumps(pr_payload()).encode()))
        with mock.patch.object(D, "build_opener", return_value=opener):
            payload = D.fetch_pr(354)
        self.assertEqual(payload["number"], 354)
        self.assertEqual(opener.request.full_url, D.API_ROOT + "354")
        self.assertEqual(opener.request.method, "GET")

    def test_identity_manifest_and_private_atomic_output(self) -> None:
        identity = D.make_manifest(354, SHA, BASE, "run-1", pr_payload())
        self.assertEqual(identity["tested_pr_head"], SHA)
        self.assertEqual(identity["tested_pr_base"], BASE)
        self.assertEqual(identity["tested_pr_head_ref"], "review")
        self.assertFalse(identity["merged"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "manifest.json"
            D.write_manifest(path, identity)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(D.read_manifest(path), identity)
            self.assertEqual(list(root.iterdir()), [path])

    def test_verify_optional_arguments_and_hardlink_rejected(self) -> None:
        identity = D.make_manifest(354, SHA, BASE, "run-1", pr_payload())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "manifest.json"
            D.write_manifest(path, identity)
            opener = Opener(Response(json.dumps(pr_payload()).encode()))
            with mock.patch.object(D, "build_opener", return_value=opener):
                self.assertEqual(D.verify_manifest(path, pr_number=354,
                                                   expected_head_sha=SHA,
                                                   dispatcher_base_sha=BASE), identity)
            hardlink = root / "hardlink.json"
            hardlink.hardlink_to(path)
            with self.assertRaises(D.ContractError):
                D.read_manifest(hardlink)

    def test_rejects_boolean_manifest_schema_version(self) -> None:
        identity = D.make_manifest(354, SHA, BASE, "run-1", pr_payload())
        identity["schema_version"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            D.write_manifest(path, identity)
            with self.assertRaisesRegex(D.ContractError, "unsupported manifest schema"):
                D.verify_manifest(path)

    def test_emit_outputs_writes_only_validated_scalars(self) -> None:
        identity = D.make_manifest(354, SHA, BASE, "run-1", pr_payload())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            output = root / "github-output"
            D.write_manifest(manifest, identity)
            output.write_bytes(b"")
            output.chmod(0o600)
            D.emit_outputs(manifest, output)
            self.assertEqual(output.read_text(),
                             f"tested_pr_head={SHA}\n"
                             f"tested_pr_base={BASE}\n"
                             f"trusted_dispatcher_base_sha={BASE}\n")

    def test_cli_locations_are_derived_from_runner_owned_environment_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "github-output"
            output.write_bytes(b"")
            with mock.patch.dict(
                D.os.environ,
                {D.RUNNER_TEMP_ENV: str(root), D.GITHUB_OUTPUT_ENV: str(output)},
                clear=True,
            ):
                self.assertEqual(
                    D._runner_manifest_path("resolve"),
                    root.joinpath(*D.RESOLVE_MANIFEST_COMPONENTS),
                )
                self.assertEqual(
                    D._runner_manifest_path("candidate"),
                    root.joinpath(*D.CANDIDATE_MANIFEST_COMPONENTS),
                )
                self.assertEqual(
                    D._runner_manifest_path("privileged"),
                    root.joinpath(*D.PRIVILEGED_MANIFEST_COMPONENTS),
                )
                self.assertEqual(D._github_output_path(), output)
                with self.assertRaises(D.ContractError):
                    D._runner_manifest_path("attacker-selected")
            with mock.patch.dict(
                D.os.environ,
                {D.RUNNER_TEMP_ENV: str(root), D.GITHUB_OUTPUT_ENV: str(root.parent / "output")},
                clear=True,
            ):
                with self.assertRaisesRegex(D.ContractError, "outside"):
                    D._github_output_path()

    def test_sha_and_runner_output_path_require_ascii_normalized_values(self) -> None:
        self.assertEqual(D.sha40(SHA, "SHA"), SHA)
        with self.assertRaises(D.ContractError):
            D.sha40("١" * 40, "SHA")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.dict(
                D.os.environ,
                {
                    D.RUNNER_TEMP_ENV: str(root),
                    D.GITHUB_OUTPUT_ENV: str(root / ".." / "output"),
                },
                clear=True,
            ):
                with self.assertRaisesRegex(D.ContractError, "unsafe"):
                    D._github_output_path()

    def test_dispatcher_source_has_no_base_exception_cleanup_handler(self) -> None:
        self.assertNotIn("BaseException", MODULE_PATH.read_text(encoding="utf-8"))

    def test_rejects_symlinked_ancestor_for_manifest_and_outputs(self) -> None:
        identity = D.make_manifest(354, SHA, BASE, "run-1", pr_payload())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir(mode=0o700)
            target = root / "target"
            target.mkdir(mode=0o700)
            (root / "alias").symlink_to(target, target_is_directory=True)
            with self.assertRaises(D.ContractError):
                D.write_manifest(root / "alias" / "manifest.json", identity)
            manifest = private / "manifest.json"
            D.write_manifest(manifest, identity)
            output = private / "github-output"
            output.write_bytes(b"")
            output.chmod(0o600)
            with self.assertRaises(D.ContractError):
                D.emit_outputs(manifest, root / "alias" / "github-output")

    def test_rejects_shared_ancestor_permissions(self) -> None:
        identity = D.make_manifest(354, SHA, BASE, "run-1", pr_payload())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir(mode=0o733)
            private.chmod(0o733)
            with self.assertRaisesRegex(D.ContractError, "not be group/world writable"):
                D.write_manifest(private / "manifest.json", identity)

    def test_accepts_runner_owned_nonwritable_directory_and_manifest(self) -> None:
        identity = D.make_manifest(354, SHA, BASE, "run-1", pr_payload())
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "runner-owned"
            private.mkdir(mode=0o755)
            manifest = private / "manifest.json"
            D.write_manifest(manifest, identity)
            manifest.chmod(0o644)
            self.assertEqual(D.read_manifest(manifest), identity)
            output = private / "github-output"
            output.write_bytes(b"")
            output.chmod(0o644)
            D.emit_outputs(manifest, output)
            output.chmod(0o622)
            with self.assertRaisesRegex(D.ContractError, "non-writable regular file"):
                D.emit_outputs(manifest, output)

    def test_merged_field_must_be_false_boolean(self) -> None:
        merged = pr_payload(merged=True)
        with self.assertRaises(D.ContractError):
            D.validate_identity(merged, 354, SHA)
        non_boolean = pr_payload(merged="false")
        with self.assertRaises(D.ContractError):
            D.validate_identity(non_boolean, 354, SHA)

    def test_rejects_changed_final_url(self) -> None:
        opener = Opener(Response(json.dumps(pr_payload()).encode(),
                                 final_url="https://api.github.com/elsewhere"))
        with mock.patch.object(D, "build_opener", return_value=opener):
            with self.assertRaises(D.ContractError):
                D.fetch_pr(354)

    def test_verify_detects_head_toctou(self) -> None:
        identity = D.make_manifest(354, SHA, BASE, "run-1", pr_payload())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            D.write_manifest(path, identity)
            changed = pr_payload(head={"ref": "review", "sha": "c" * 40,
                                       "repo": {"full_name": D.CANONICAL_REPOSITORY}})
            opener = Opener(Response(json.dumps(changed).encode()))
            with mock.patch.object(D, "build_opener", return_value=opener):
                with self.assertRaises(D.ContractError):
                    D.verify_manifest(path)

    def test_verify_detects_base_toctou(self) -> None:
        identity = D.make_manifest(354, SHA, BASE, "run-1", pr_payload())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            D.write_manifest(path, identity)
            changed = pr_payload(base={
                "ref": "master", "sha": "c" * 40,
                "repo": {"full_name": D.CANONICAL_REPOSITORY},
            })
            opener = Opener(Response(json.dumps(changed).encode()))
            with mock.patch.object(D, "build_opener", return_value=opener):
                with self.assertRaisesRegex(D.ContractError, "identity changed"):
                    D.verify_manifest(path)

    def test_dispatch_identity_is_fail_closed_for_a_changed_exact_head(self) -> None:
        changed = pr_payload(head={
            "ref": "review", "sha": "c" * 40,
            "repo": {"full_name": D.CANONICAL_REPOSITORY},
        })
        with self.assertRaisesRegex(D.ContractError, "stale|does not match"):
            D.make_manifest(354, SHA, BASE, "run-1", changed)

    def test_rejects_malformed_duplicate_and_oversized_json(self) -> None:
        with self.assertRaises(D.ContractError):
            self.fetch(b'{"number":354,"number":354}')
        with self.assertRaises(D.ContractError):
            self.fetch(b"{")
        with self.assertRaises(D.ContractError):
            self.fetch(b"{}", {"Content-Length": str(D.MAX_RESPONSE_BYTES + 1)})
        with self.assertRaises(D.ContractError):
            self.fetch(b"x" * (D.MAX_RESPONSE_BYTES + 1))

    def test_rejects_redirect_and_invalid_pr_states(self) -> None:
        class Redirect(Opener):
            def open(self, request: object, timeout: int) -> Response:
                raise D.ContractError("redirect")
        with mock.patch.object(D, "build_opener", return_value=Redirect(Response(b"{}"))):
            with self.assertRaises(D.ContractError):
                D.fetch_pr(354)
        for update in ({"state": "closed"}, {"merged_at": "2026-01-01T00:00:00Z"},
                       {"draft": "true"}):
            payload = pr_payload(**update)
            with self.assertRaises(D.ContractError):
                D.validate_identity(payload, 354, SHA)

    def test_rejects_short_sha_foreign_head_and_wrong_base(self) -> None:
        cases = [
            {"head": {"ref": "review", "sha": "a", "repo": {"full_name": D.CANONICAL_REPOSITORY}}},
            {"head": {"ref": "review", "sha": SHA, "repo": {"full_name": "other/fork"}}},
            {"base": {"ref": "main", "sha": BASE, "repo": {"full_name": D.CANONICAL_REPOSITORY}}},
            {"head": {"ref": "refs/heads/review", "sha": SHA, "repo": {"full_name": D.CANONICAL_REPOSITORY}}},
        ]
        for update in cases:
            payload = pr_payload(**update)
            with self.subTest(update=update):
                with self.assertRaises(D.ContractError):
                    D.validate_identity(payload, 354, SHA)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
