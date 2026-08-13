"""Hermetic descriptor-resolver coverage for atomic common.sh provenance."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
from http.client import RemoteDisconnected
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "ci/tools/check-common-versions.py"
CURRENT_DIGEST = "a" * 64
LATEST_DIGEST = "b" * 64


def load_checker():
    spec = importlib.util.spec_from_file_location("check_common_versions", CHECKER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load common-version checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


class FixtureClient:
    def __init__(self, json_responses=None, text_responses=None):
        self.json_responses = json_responses or {}
        self.text_responses = text_responses or {}
        self.urls = []

    def get_json(self, url):
        self.urls.append(url)
        return self.json_responses[url]

    def get_text(self, url, accept=None):
        del accept
        self.urls.append(url)
        return self.text_responses[url]

    get_checksum_text = get_text


def parse_entries(source: str):
    with tempfile.TemporaryDirectory(prefix="atomic-provenance-") as temporary:
        fixture = Path(temporary) / "common.sh"
        fixture.write_text(source, encoding="utf-8")
        _, entries = CHECKER.parse_common(fixture)
    return entries


def assignment(name: str, value: str) -> str:
    return f'{name}="${{{name}:-{value}}}"'


def github_asset(repository: str, tag: str, name: str) -> str:
    return f"https://github.com/{repository}/releases/download/{tag}/{name}"


class CommonVersionAtomicProvenanceTests(unittest.TestCase):
    def github_entries(self, component: str, version: str = "1.0.0"):
        definition = CHECKER.COMPONENT_DEFINITION_BY_NAME[component]
        tag = f"{definition.tag_prefix}{version}"
        asset = definition.asset_template.format(version=version)
        values = {}
        for variable in definition.variables:
            if variable == definition.version_variable:
                values[variable] = version
            elif variable == definition.source_url_variable:
                values[variable] = (
                    f"https://github.com/{definition.github_repository}/releases"
                    if component in {"Envoy", "Traefik"}
                    else github_asset(definition.github_repository, tag, asset)
                )
            elif variable == definition.download_url_variable:
                values[variable] = github_asset(definition.github_repository, tag, asset)
            elif variable == definition.sha256_variable:
                values[variable] = CURRENT_DIGEST
            elif variable == definition.sha256_url_variable:
                values[variable] = (
                    github_asset(
                        definition.github_repository,
                        tag,
                        definition.checksum_asset_template.format(version=version),
                    )
                    if definition.checksum_asset_template
                    else ""
                )
            else:
                raise AssertionError(f"unhandled fixture variable {variable}")
        return definition, parse_entries("\n".join(assignment(*item) for item in values.items()))

    def latest_release(self, definition, version="1.0.1", *, draft=False, prerelease=False):
        tag = f"{definition.tag_prefix}{version}"
        asset = definition.asset_template.format(version=version)
        assets = [{"name": asset, "browser_download_url": github_asset(definition.github_repository, tag, asset), "digest": f"sha256:{LATEST_DIGEST}"}]
        if definition.checksum_asset_template:
            checksum = definition.checksum_asset_template.format(version=version)
            assets.append({"name": checksum, "browser_download_url": github_asset(definition.github_repository, tag, checksum)})
        return tag, {"tag_name": tag, "draft": draft, "prerelease": prerelease, "assets": assets}

    def test_github_components_produce_complete_atomic_updates(self):
        for component in ("PCRE2", "OpenSSL for NGINX QUIC/TLS", "Envoy", "Traefik"):
            with self.subTest(component=component):
                definition, entries = self.github_entries(component)
                tag, release = self.latest_release(definition)
                manifests = {}
                if definition.checksum_asset_template:
                    checksum = definition.checksum_asset_template.format(version="1.0.1")
                    manifests[github_asset(definition.github_repository, tag, checksum)] = f"{LATEST_DIGEST}  {definition.asset_template.format(version='1.0.1')}\n"
                client = FixtureClient(
                    {f"https://api.github.com/repos/{definition.github_repository}/releases/latest": release}, manifests
                )
                result = CHECKER.resolve_component_definition(definition, entries, client)

                self.assertEqual(CHECKER.STATUS_OUTDATED, result.status)
                decorated = CHECKER.decorate_component_result(definition, result, entries)
                expected = decorated.details["atomic_expected_values"]
                self.assertEqual(set(expected), set(definition.atomic_group))
                self.assertEqual(
                    {change.variable: change.new for change in result.updates},
                    {
                        variable: value
                        for variable, value in expected.items()
                        if entries[variable].default != value
                    },
                )

    def test_traefik_prefers_github_asset_digest_before_manifest_download(self):
        definition, entries = self.github_entries("Traefik")
        _, release = self.latest_release(definition)
        latest_endpoint = (
            f"https://api.github.com/repos/{definition.github_repository}/releases/latest"
        )
        client = FixtureClient(json_responses={latest_endpoint: release})

        result = CHECKER.resolve_component_definition(definition, entries, client)

        self.assertEqual(result.status, CHECKER.STATUS_OUTDATED)
        self.assertEqual(result.sha256_source, "github_release_asset_digest")
        self.assertEqual(client.urls, [latest_endpoint])

    def test_draft_prerelease_and_ambiguous_assets_reject_before_any_update(self):
        definition, entries = self.github_entries("PCRE2")
        for label, release in (
            ("draft", self.latest_release(definition, draft=True)[1]),
            ("prerelease", self.latest_release(definition, prerelease=True)[1]),
            ("ambiguous", {**self.latest_release(definition)[1], "assets": self.latest_release(definition)[1]["assets"] * 2}),
        ):
            with self.subTest(label=label):
                results = CHECKER.check_all(entries, FixtureClient({f"https://api.github.com/repos/{definition.github_repository}/releases/latest": release}), (definition.name,))
                self.assertEqual(CHECKER.STATUS_UNKNOWN, results[0].status)
                self.assertEqual(results[0].updates, [])

    def test_lighttpd_series_update_is_atomic_and_uses_only_official_urls(self):
        source = "\n".join((
            assignment("LIGHTTPD_VERSION", "1.4.80"),
            assignment("LIGHTTPD_SOURCE_URL", "https://download.lighttpd.net/lighttpd/releases-1.4.x/"),
            assignment("LIGHTTPD_RELEASE_INDEX_URL", "https://download.lighttpd.net/lighttpd/releases-1.4.x/"),
            assignment("LIGHTTPD_LATEST_URL", "https://download.lighttpd.net/lighttpd/releases-1.4.x/latest.txt"),
            assignment("LIGHTTPD_DOWNLOAD_URL", "https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.80.tar.xz"),
            assignment("LIGHTTPD_SHA256", CURRENT_DIGEST),
            assignment("LIGHTTPD_SHA256_URL", "https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.80.sha256sum"),
        ))
        entries = parse_entries(source)
        base = "https://download.lighttpd.net/lighttpd/releases-1.4.x/"
        result = CHECKER.check_lighttpd(entries, FixtureClient(text_responses={base + "latest.txt": "lighttpd-1.4.81.tar.xz\n", base + "lighttpd-1.4.81.sha256sum": f"{LATEST_DIGEST}  lighttpd-1.4.81.tar.xz\n"}))
        self.assertEqual(CHECKER.STATUS_OUTDATED, result.status)
        self.assertEqual({item.variable for item in result.updates}, {"LIGHTTPD_VERSION", "LIGHTTPD_SHA256"})

    def test_apr_util_164_to_165_updates_only_its_dynamic_tuple_authorities(self):
        apr_source = "https://downloads.apache.org/apr/"
        expected_digest = "96de1dd6f6a0476d2d2e7964926d8c1ddc3bb0e210e1b1812d3ba5a454a392e2"
        entries = parse_entries("\n".join((
            assignment("APR_UTIL_VERSION", "1.6.4"),
            assignment("APR_UTIL_SOURCE_URL", "https://downloads.apache.org/apr/apr-util-$APR_UTIL_VERSION.tar.bz2"),
            assignment("APR_UTIL_SHA256", CURRENT_DIGEST),
            assignment("APR_UTIL_SHA256_URL", "$APR_UTIL_SOURCE_URL.sha256"),
        )))
        client = FixtureClient(text_responses={
            apr_source: "apr-util-1.6.4.tar.bz2 apr-util-1.6.5.tar.bz2",
            apr_source + "apr-util-1.6.5.tar.bz2.sha256": f"{expected_digest}  apr-util-1.6.5.tar.bz2\n",
        })

        result = CHECKER.check_all(entries, client, ("APR-util",))[0]

        self.assertEqual(CHECKER.STATUS_OUTDATED, result.status)
        self.assertEqual(result.latest_upstream, "1.6.5")
        self.assertEqual(result.latest_compatible, "1.6.5")
        self.assertEqual(result.official_sha256, expected_digest)
        self.assertEqual(
            {change.variable: change.new for change in result.updates},
            {"APR_UTIL_VERSION": "1.6.5", "APR_UTIL_SHA256": expected_digest},
        )
        self.assertEqual(
            result.details["atomic_expected_values"],
            {
                "APR_UTIL_VERSION": "1.6.5",
                "APR_UTIL_SOURCE_URL": "https://downloads.apache.org/apr/apr-util-$APR_UTIL_VERSION.tar.bz2",
                "APR_UTIL_SHA256": expected_digest,
                "APR_UTIL_SHA256_URL": "$APR_UTIL_SOURCE_URL.sha256",
            },
        )

    def test_invalid_apr_util_upstream_checksum_never_produces_an_update(self):
        apr_source = "https://downloads.apache.org/apr/"
        entries = parse_entries("\n".join((
            assignment("APR_UTIL_VERSION", "1.6.4"),
            assignment("APR_UTIL_SOURCE_URL", "https://downloads.apache.org/apr/apr-util-$APR_UTIL_VERSION.tar.bz2"),
            assignment("APR_UTIL_SHA256", CURRENT_DIGEST),
            assignment("APR_UTIL_SHA256_URL", "$APR_UTIL_SOURCE_URL.sha256"),
        )))
        result = CHECKER.check_all(entries, FixtureClient(text_responses={
            apr_source: "apr-util-1.6.4.tar.bz2 apr-util-1.6.5.tar.bz2",
            apr_source + "apr-util-1.6.5.tar.bz2.sha256": "sha1  apr-util-1.6.5.tar.bz2\n",
        }), ("APR-util",))[0]

        self.assertEqual(CHECKER.STATUS_UNKNOWN, result.status)
        self.assertEqual(result.updates, [])

    def test_manual_git_release_requires_the_tag_peeled_commit_to_match(self):
        repository = "owasp-modsecurity/ModSecurity"
        current_tag = "v3.0.15"
        latest_tag = "v3.0.16"
        current_commit = "c" * 40
        annotated_tag_object = "a" * 40
        latest_commit = "d" * 40
        entries = parse_entries("\n".join((
            assignment("MODSECURITY_V3_APPROVED_REPO_URL", f"https://github.com/{repository}.git"),
            assignment("MODSECURITY_V3_RELEASE_TAG", current_tag),
            assignment("MODSECURITY_V3_APPROVED_COMMIT", current_commit),
            assignment("MODSECURITY_REPO_URL", f"https://github.com/{repository}.git"),
            assignment("MODSECURITY_GIT_REF", current_tag),
            assignment("MODSECURITY_V3_GIT_URL", f"https://github.com/{repository}.git"),
            assignment("MODSECURITY_V3_GIT_REF", current_tag),
        )))
        base = f"https://api.github.com/repos/{repository}"
        client = FixtureClient(json_responses={
            f"{base}/git/ref/tags/{current_tag}": {
                "object": {"type": "tag", "sha": annotated_tag_object},
            },
            f"{base}/git/tags/{annotated_tag_object}": {
                "object": {"type": "commit", "sha": current_commit},
            },
            f"{base}/releases/latest": {
                "tag_name": latest_tag,
                "draft": False,
                "prerelease": False,
            },
            f"{base}/git/ref/tags/{latest_tag}": {
                "object": {"type": "commit", "sha": latest_commit},
            },
        })

        result = CHECKER.check_all(entries, client, ("ModSecurity v3",))[0]

        self.assertEqual(CHECKER.STATUS_REVIEW_REQUIRED, result.status)
        self.assertEqual(result.details["current_peeled_commit"], current_commit)
        self.assertEqual(result.details["latest_peeled_commit"], latest_commit)
        self.assertEqual(result.updates, [])

    def test_checksum_parser_rejects_html_malformed_and_ambiguous_entries(self):
        expected_name = "component-1.0.1.tar.gz"
        valid = f"{LATEST_DIGEST}  {expected_name}\n"
        for label, checksum in (
            ("html", "<html>not a checksum</html>"),
            ("wrong-algorithm", f"sha1  {expected_name}\n"),
            ("duplicate", valid + valid),
        ):
            with self.subTest(label=label):
                with self.assertRaises((CHECKER.UpstreamBlocked, CHECKER.UpstreamUnknown)):
                    CHECKER.parse_sha256(checksum, expected_name)

    def test_http_client_rejects_redirected_or_non_checksum_responses(self):
        class Headers:
            def __init__(self, content_type, charset="utf-8"):
                self.content_type = content_type
                self.charset = charset

            def get_content_type(self):
                return self.content_type

            def get_content_charset(self):
                return self.charset

        class Response:
            def __init__(self, final_url, content_type, charset="utf-8"):
                self.final_url = final_url
                self.headers = Headers(content_type, charset)

            def __enter__(self):
                return self

            def __exit__(self, *unused):
                return False

            def geturl(self):
                return self.final_url

            def read(self):
                return b"{}"

        class Opener:
            def __init__(self, response):
                self.response = response

            def open(self, request, timeout):
                del request, timeout
                return self.response

        class DisconnectingOpener:
            def open(self, request, timeout):
                del request, timeout
                raise RemoteDisconnected("fixture peer closed the connection")

        url = "https://downloads.example.invalid/component.sha256"
        client = CHECKER.HttpClient(timeout=1)
        client._opener = Opener(Response("https://other.example.invalid/component.sha256", "text/plain"))
        with self.assertRaises(CHECKER.UpstreamUnknown):
            client.get_checksum_text(url)

        client._opener = Opener(Response(url, "text/html"))
        with self.assertRaises(CHECKER.UpstreamUnknown):
            client.get_checksum_text(url)

        client._opener = Opener(Response(url, "text/plain", "unsupported-charset"))
        with self.assertRaises(CHECKER.UpstreamUnknown):
            client.get_checksum_text(url)

        client._opener = DisconnectingOpener()
        with self.assertRaises(CHECKER.UpstreamBlocked):
            client.get_checksum_text(url)

    def test_registry_covers_every_relevant_common_sh_provenance_variable(self):
        _, entries = CHECKER.parse_common(ROOT / "ci/lib/common.sh")
        self.assertEqual(CHECKER.unassigned_provenance_variables(entries), [])
        nginx = CHECKER.COMPONENT_DEFINITION_BY_NAME["NGINX"]
        self.assertNotIn("NGINX_SHA256_REQUESTED", nginx.variables)
        self.assertEqual({item.name for item in CHECKER.COMPONENT_DEFINITIONS}, set(CHECKER.COMPONENT_DEFINITION_BY_NAME))

    def test_production_open_ssl_and_nginx_asset_urls_remain_version_derived(self):
        _, entries = CHECKER.parse_common(ROOT / "ci/lib/common.sh")
        open_ssl_source = entries["NGINX_QUIC_TLS_SOURCE_URL"]
        nginx_asset = entries["NGINX_RELEASE_ASSET_NAME"]

        self.assertIn("$NGINX_QUIC_TLS_VERSION", open_ssl_source.default)
        self.assertIn(
            CHECKER.value(entries, "NGINX_QUIC_TLS_VERSION"),
            open_ssl_source.resolved,
        )
        self.assertTrue(
            CHECKER.is_template_value(
                open_ssl_source.default, "NGINX_QUIC_TLS_VERSION"
            )
        )
        self.assertIn("${NGINX_RELEASE_TAG#release-}", nginx_asset.default)
        self.assertEqual(
            nginx_asset.resolved,
            "nginx-" + CHECKER.value(entries, "NGINX_RELEASE_TAG").removeprefix("release-") + ".tar.gz",
        )

    def test_fatal_result_never_writes_and_second_application_is_idempotent(self):
        with tempfile.TemporaryDirectory(prefix="atomic-provenance-") as temporary:
            root = Path(temporary)
            target = root / "build" / "common.sh"
            target.parent.mkdir(parents=True)
            target.write_text(assignment("VERSION", "1.0") + "\n", encoding="utf-8")
            lines, entries = CHECKER.parse_common(target)
            fatal = CHECKER.ComponentResult("fatal", CHECKER.STATUS_UNKNOWN, "fixture", [])
            original = target.read_text(encoding="utf-8")
            previous_build_root = CHECKER.os.environ.get("BUILD_ROOT")
            CHECKER.os.environ["BUILD_ROOT"] = str(root / "build")
            try:
                rc, updates, _, _ = CHECKER.apply_requested_updates(True, 2, target, lines, entries, [fatal], defer_reviewed_provenance=True)
                self.assertEqual((rc, updates), (2, []))
                self.assertEqual(target.read_text(encoding="utf-8"), original)
                current = CHECKER.ComponentResult("current", CHECKER.STATUS_CURRENT, "fixture", [])
                rc, updates, _, _ = CHECKER.apply_requested_updates(True, 0, target, lines, entries, [current], defer_reviewed_provenance=True)
                self.assertEqual((rc, updates), (0, []))
                self.assertEqual(target.read_text(encoding="utf-8"), original)
            finally:
                if previous_build_root is None:
                    del CHECKER.os.environ["BUILD_ROOT"]
                else:
                    CHECKER.os.environ["BUILD_ROOT"] = previous_build_root

    def test_atomic_candidate_write_keeps_original_on_replace_failure(self):
        with tempfile.TemporaryDirectory(prefix="atomic-provenance-write-") as temporary:
            build_root = Path(temporary) / "build"
            target = build_root / "common.sh"
            target.parent.mkdir(parents=True)
            target.write_text(assignment("VERSION", "1.0") + "\n", encoding="utf-8")
            target.chmod(0o755)
            lines, entries = CHECKER.parse_common(target)
            update = CHECKER.plan_update(entries, "VERSION", "1.1")
            self.assertIsNotNone(update)
            original = target.read_bytes()
            with patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=False), patch.object(CHECKER.os, "replace", side_effect=OSError("injected replace failure")):
                with self.assertRaises(OSError):
                    CHECKER.apply_updates(target, lines, [update])

            self.assertEqual(target.read_bytes(), original)
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)
            self.assertEqual(list(target.parent.glob(".common.sh.*.tmp")), [])

    def test_cli_component_filter_check_update_exit_codes_and_second_run_are_idempotent(self):
        class AprUtilClient:
            def __init__(self, timeout):
                self.timeout = timeout

            def get_text(self, url, accept=None):
                del accept
                responses = {
                    "https://downloads.apache.org/apr/": "apr-util-1.6.4.tar.bz2 apr-util-1.6.5.tar.bz2",
                    "https://downloads.apache.org/apr/apr-util-1.6.5.tar.bz2.sha256": (
                        "96de1dd6f6a0476d2d2e7964926d8c1ddc3bb0e210e1b1812d3ba5a454a392e2"
                        "  apr-util-1.6.5.tar.bz2\n"
                    ),
                }
                return responses[url]

            get_checksum_text = get_text

        with tempfile.TemporaryDirectory(prefix="atomic-provenance-cli-") as temporary:
            build_root = Path(temporary) / "build"
            target = build_root / "common.sh"
            target.parent.mkdir(parents=True)
            target.write_text("\n".join((
                assignment("APR_UTIL_VERSION", "1.6.4"),
                assignment("APR_UTIL_SOURCE_URL", "https://downloads.apache.org/apr/apr-util-$APR_UTIL_VERSION.tar.bz2"),
                assignment("APR_UTIL_SHA256", CURRENT_DIGEST),
                assignment("APR_UTIL_SHA256_URL", "$APR_UTIL_SOURCE_URL.sha256"),
                "",
            )), encoding="utf-8")
            initial_bytes = target.read_bytes()
            output = io.StringIO()
            errors = io.StringIO()
            with patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=False), patch.object(CHECKER, "HttpClient", AprUtilClient), redirect_stdout(output), redirect_stderr(errors):
                check_rc = CHECKER.main([
                    "--check", "--json", "--component", "APR-util", "--common-sh", str(target),
                ])
            check_summary = json.loads(output.getvalue())
            checked_bytes = target.read_bytes()

            output = io.StringIO()
            with patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=False), patch.object(CHECKER, "HttpClient", AprUtilClient), redirect_stdout(output), redirect_stderr(io.StringIO()):
                first_rc = CHECKER.main([
                    "--update", "--json", "--component", "APR-util", "--common-sh", str(target),
                ])
            first_summary = json.loads(output.getvalue())
            first_bytes = target.read_bytes()

            output = io.StringIO()
            with patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=False), patch.object(CHECKER, "HttpClient", AprUtilClient), redirect_stdout(output), redirect_stderr(io.StringIO()):
                second_rc = CHECKER.main([
                    "--update", "--json", "--component", "APR-util", "--common-sh", str(target),
                ])
            second_summary = json.loads(output.getvalue())
            second_bytes = target.read_bytes()

        self.assertEqual(check_rc, 1)
        self.assertEqual(check_summary["maintenance_outcome"], "safe_updates")
        self.assertEqual(checked_bytes, initial_bytes)
        self.assertEqual(first_rc, 0)
        self.assertEqual(second_rc, 0)
        self.assertEqual(first_summary["selected_components"], ["APR-util"])
        self.assertEqual(
            [change["variable"] for change in first_summary["updates_applied"]],
            ["APR_UTIL_VERSION", "APR_UTIL_SHA256"],
        )
        self.assertEqual(second_summary["updates_applied"], [])
        self.assertEqual(first_bytes, second_bytes)

    def test_list_components_and_unknown_component_are_deterministic(self):
        self.assertEqual(
            CHECKER.canonical_component_selection(["PCRE2", "APR-util", "PCRE2"]),
            ("APR-util", "PCRE2"),
        )
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(CHECKER.main(["--list-components"]), 0)
        self.assertEqual(
            output.getvalue().splitlines(),
            [definition.name for definition in CHECKER.COMPONENT_DEFINITIONS],
        )
        self.assertEqual(CHECKER.main(["--component", "not-a-component"]), 2)


if __name__ == "__main__":
    unittest.main()
