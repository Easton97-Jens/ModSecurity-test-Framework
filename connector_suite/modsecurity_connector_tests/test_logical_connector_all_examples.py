"""Regression coverage for comprehensive logical-connector examples.

The existing matrix checker deliberately covers the CI-owned three-profile
layout.  This test owns the fourth, configuration-completeness `all` layout
without redefining `phase4_mode`: every materialized profile must keep a real
`strict` value and its source-backed P1--P4/companion boundary.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import re
import tempfile
import unittest
from pathlib import Path
from shutil import copytree


ROOT = connector_root()
RESPONSE_OBSERVER_SERVICE = source_path('connectors/envoy/ext_proc/internal/responseobserver/service.go', root=ROOT)
RESPONSE_OBSERVER_PROTOCOL_TEST = (
    source_path('connectors/envoy/ext_proc/internal/responseobserver/protocol_test.go', root=ROOT)
)
THREE_VARIANTS = ("off", "safe", "strict")
INVALID_PHASE4_VALUES = (
    "phase4_mode=all",
    "phase4-mode all",
    "modsecurity_phase4_mode all",
)
UNSAFE_TRANSACTION_ID_VALUES = (
    "%{REQUEST_URI}",
    "$request_uri",
)
ROOT_EXAMPLE_READMES = (
    source_path('examples/README.md', root=ROOT),
    source_path('examples/README.de.md', root=ROOT),
)
ROOT_ALL_PATHS = (
    "apache/all/httpd.conf",
    "nginx/all/nginx.conf",
    "haproxy/all/haproxy-htx.cfg",
    "haproxy/spoe-spop/all/",
    "envoy/ext-authz/all/",
    "envoy/ext-proc/all/",
    "traefik/forwardauth/all/",
    "traefik/native-uds/all/",
    "lighttpd/stock/all/",
    "lighttpd/patched/all/",
)
ROOT_COMPATIBILITY_LINKS = (
    "haproxy/README.md#spoespop-compatibility-material",
    "envoy/README.md#ext_authz-compatibility",
    "traefik/README.md#forwardauth-compatibility",
    "lighttpd/README.md#sidecar-compatibility",
)
ROOT_COMPATIBILITY_LINKS_DE = (
    "haproxy/README.de.md#spoespop-kompatibilitätsmaterial",
    "envoy/README.de.md#ext_authz-kompatibilität",
    "traefik/README.de.md#forwardauth-kompatibilität",
    "lighttpd/README.de.md#sidecar-kompatibilität",
)
CONNECTOR_NAVIGATION_DOCS = (
    (
        source_path('docs/connectors/README.md', root=ROOT),
        "six host integrations and ten logical connector",
        "Logical profile inventory",
    ),
    (
        source_path('docs/connectors/README.de.md', root=ROOT),
        "sechs Hostintegrationen und zehn logische",
        "Inventar der logischen Profile",
    ),
)
LOGICAL_PROFILE_IDS = (
    "apache",
    "nginx",
    "haproxy-htx",
    "haproxy-spoe-spop",
    "envoy-ext-authz",
    "envoy-ext-proc",
    "traefik-forwardauth",
    "traefik-native-uds",
    "lighttpd-stock",
    "lighttpd-patched",
)


PROFILE_MATRIX = {
    "apache": {
        "directory": "examples/apache",
        "files": ("httpd.conf",),
        "required": (
            "LoadModule security3_module",
            "modsecurity on",
            "modsecurity_rules_file",
            "modsecurity_use_error_log on",
            "modsecurity_phase4_mode strict",
            "modsecurity_phase4_log",
            "modsecurity_transaction_id_expr",
            "modsecurity_transaction_id example-apache-transaction",
            "modsecurity_rules_remote key",
        ),
    },
    "nginx": {
        "directory": "examples/nginx",
        "files": ("nginx.conf",),
        "required": (
            "load_module",
            "modsecurity on",
            "modsecurity_rules_file",
            "modsecurity_phase4_mode strict",
            "modsecurity_phase4_log",
            "modsecurity_use_error_log on",
            "modsecurity_transaction_id",
            "modsecurity_rules_remote key",
            "listen 127.0.0.1:8080;",
        ),
    },
    "haproxy-htx": {
        "directory": "examples/haproxy",
        "files": ("haproxy-htx.cfg",),
        "required": (
            "filter modsecurity-htx",
            "rules-file",
            "phase4-mode strict",
            "bind 127.0.0.1",
        ),
    },
    "haproxy-spoe-spop": {
        "directory": "examples/haproxy/spoe-spop",
        "files": ("haproxy.cfg", "spoa-agent.conf", "spoe.cfg"),
        "required": (
            "filter spoe engine modsecurity",
            "filter modsecurity-htx",
            "response-companion=native-htx",
            "response-companion-socket",
            "response-companion-uid=1000",
            "response-companion-gid=1000",
            "phase4-mode strict",
            "response-phases=true",
            "http-request redirect location",
            "http-request silent-drop",
            "http-request deny status 401",
            "http-request deny status 406",
            "http-request deny status 429",
            "http-request deny status 503",
        ),
    },
    "envoy-ext-authz": {
        "directory": "examples/envoy/ext-authz",
        "files": ("envoy.yaml.in", "msconnector-runtime.conf"),
        "required": (
            "envoy.filters.http.ext_authz",
            "response_observer",
            "request_body_mode=buffered",
            "response_body_mode=streaming",
            "phase4_mode=strict",
            "rules_inline=SecRuleEngine On",
            "rules_remote_url=https://rules.invalid/reviewed/no-crs.conf",
            "transaction_id=operator-supplied-id",
            "late_intervention_timeout=5000",
            "event_path=/var/log/modsecurity/envoy-ext-authz-all-events.jsonl",
            "max_event_json_bytes=16384",
        ),
    },
    "envoy-ext-proc": {
        "directory": "examples/envoy/ext-proc",
        "files": ("envoy.yaml.in", "service.json", "msconnector-runtime.conf"),
        "required": (
            "envoy.filters.http.ext_proc",
            "request_body_mode: STREAMED",
            "response_body_mode: STREAMED",
            '"late_action_policy": "strict"',
            "request_body_mode=streaming",
            "response_body_mode=streaming",
            "phase4_mode=strict",
            "rules_inline=SecRuleEngine On",
            "rules_remote_url=https://rules.invalid/reviewed/no-crs.conf",
            "transaction_id=operator-supplied-id",
            "late_intervention_timeout=5000",
            "event_path=/var/log/modsecurity/envoy-ext-proc-all-events.jsonl",
        ),
    },
    "traefik-forwardauth": {
        "directory": "examples/traefik/forwardauth",
        "files": ("traefik-static.yaml", "traefik-dynamic.yaml", "traefik-engine-service.conf"),
        "required": (
            "forwardBody: true",
            "maxBodySize: 4096",
            "modsecurityResponseObserver",
            "socketPath:",
            "request_body_mode=buffered",
            "response_body_mode=streaming",
            "phase4_mode=strict",
        ),
    },
    "traefik-native-uds": {
        "directory": "examples/traefik/native-uds",
        "files": ("traefik-static.yaml", "traefik-dynamic.yaml", "traefik-engine-service.conf"),
        "required": (
            "modsecurityNative",
            "engineMode: uds",
            "engineSocketPath:",
            "request_body_mode=streaming",
            "response_body_mode=streaming",
            "phase4_mode=strict",
        ),
    },
    "lighttpd-stock": {
        "directory": "examples/lighttpd/stock",
        "files": ("lighttpd-backend.conf", "stock-sidecar.args", "msconnector-runtime.conf"),
        "required": (
            "--listen 127.0.0.1",
            "--upstream 127.0.0.1",
            "request_body_mode=streaming",
            "response_body_mode=streaming",
            "phase4_mode=strict",
            "max_event_json_bytes=16384",
        ),
    },
    "lighttpd-patched": {
        "directory": "examples/lighttpd/patched",
        "files": ("lighttpd.conf", "msconnector-runtime.conf"),
        "required": (
            "mod_msconnector",
            "msconnector.config-file",
            "msconnector.request-body-gate = \"pre-upstream\"",
            "request_body_mode=streaming",
            "response_body_mode=streaming",
            "phase4_mode=strict",
            "max_event_json_bytes=16384",
        ),
    },
}


def _all_paths(profile: dict[str, tuple[str, ...] | str], root: Path) -> tuple[Path, ...]:
    return tuple(root / profile["directory"] / "all" / name for name in profile["files"])


def all_example_errors(root: Path) -> list[str]:
    """Return every materialization/configuration-completeness violation."""
    errors: list[str] = []
    for name, profile in PROFILE_MATRIX.items():
        paths = _all_paths(profile, root)
        missing = [str(path.relative_to(root)) for path in paths if not path.is_file()]
        if missing:
            errors.append(f"{name}/all: missing artifact(s): {', '.join(missing)}")
            continue
        text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        for token in profile["required"]:
            if token not in text:
                errors.append(f"{name}/all: missing source-backed parameter {token!r}")
        for invalid in INVALID_PHASE4_VALUES:
            if invalid in text:
                errors.append(f"{name}/all: unsupported phase4 value {invalid!r}")
        if any(value in text for value in UNSAFE_TRANSACTION_ID_VALUES):
            errors.append(f"{name}/all: request-controlled transaction identifier is forbidden")
        if "0.0.0.0" in text:
            errors.append(f"{name}/all: public default binding is forbidden")
        if name == "nginx" and re.search(
            r"(?m)^\s*listen\s+(?!127\.0\.0\.1:)", text
        ):
            errors.append(f"{name}/all: public default binding is forbidden")
    return errors


class LogicalConnectorAllExamplesTests(unittest.TestCase):
    def test_removed_phase4_body_limit_is_absent_from_host_examples(self) -> None:
        for connector, filename in (("apache", "httpd.conf"), ("nginx", "nginx.conf")):
            for variant in (*THREE_VARIANTS, "all"):
                path = source_path('examples', root=ROOT) / connector / variant / filename
                with self.subTest(path=path):
                    text = path.read_text()
                    self.assertNotIn("modsecurity_phase4_body_limit", text)
                    self.assertNotIn("configurable 1 MiB byte cap", text)
                    self.assertNotIn("explicit response bound", text)

    def test_connector_navigation_docs_preserve_all_ten_logical_profiles(self) -> None:
        for path, host_navigation_text, inventory_heading in CONNECTOR_NAVIGATION_DOCS:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIn(host_navigation_text, text)
                self.assertIn(inventory_heading, text)
                for profile in LOGICAL_PROFILE_IDS:
                    self.assertIn(f"<code>{profile}</code>", text)

        manifest = json.loads(
            (source_path('connectors/lighttpd/capabilities.json', root=ROOT)).read_text(encoding="utf-8")
        )
        self.assertEqual(
            manifest["transaction_contract_profiles"],
            ["lighttpd-stock", "lighttpd-patched"],
        )
        self.assertEqual(
            manifest["logical_routes"]["lighttpd-stock"]["integration_mode"],
            "stock-lighttpd-sidecar",
        )
        self.assertIn("canonical logical Stock profile", manifest["host_model_constraints"][-1])

    def test_root_documentation_catalogues_all_ten_logical_solutions(self) -> None:
        english = ROOT_EXAMPLE_READMES[0].read_text(encoding="utf-8")
        german = ROOT_EXAMPLE_READMES[1].read_text(encoding="utf-8")
        documents = (
            (ROOT_EXAMPLE_READMES[0], "| Logical connector solution |", english),
            (ROOT_EXAMPLE_READMES[1], "| Logische Connectorlösung |", german),
        )
        for readme, heading, text in documents:
            with self.subTest(readme=readme.name):
                self.assertIn(heading, text)
                for relative_path in ROOT_ALL_PATHS:
                    self.assertIn(f"({relative_path})", text)
        for relative_path in ROOT_COMPATIBILITY_LINKS:
            self.assertIn(f"({relative_path})", english)
        for relative_path in ROOT_COMPATIBILITY_LINKS_DE:
            self.assertIn(f"({relative_path})", german)
        self.assertIn("never introduces an unsupported `all` phase", english)
        self.assertIn("keinen nicht unterstützten P4-Modus `all`", german)

    def test_all_profiles_are_materialized_with_real_phase4_values(self) -> None:
        self.assertEqual(all_example_errors(ROOT), [])
        service = json.loads(
            (source_path('examples/envoy/ext-proc/all/service.json', root=ROOT)).read_text(encoding="utf-8")
        )
        self.assertEqual(service["late_action_policy"], "strict")
        self.assertEqual(service["max_header_count"], 128)
        self.assertEqual(service["max_body_chunk_bytes"], 1048576)

    def test_ext_authz_response_handle_is_removed_before_upstream(self) -> None:
        configuration = (
            source_path('examples/envoy/ext-authz/all/envoy.yaml.in', root=ROOT)
        ).read_text(encoding="utf-8")
        service = RESPONSE_OBSERVER_SERVICE.read_text(encoding="utf-8")
        protocol_test = RESPONSE_OBSERVER_PROTOCOL_TEST.read_text(encoding="utf-8")

        self.assertIn("allowed_upstream_headers", configuration)
        self.assertIn("cluster_name: msconnector_response_observer", configuration)
        self.assertIn("request_header_mode: SEND", configuration)
        self.assertRegex(
            service,
            r'(?m)^\s*DefaultHandleHeader\s*=\s*"x-msconnector-response-handle"\s*$',
        )
        self.assertIn("mutation.RemoveHeaders = []string{handleHeader}", service)
        self.assertIn("func TestRequestHandleMutationStripsOpaqueHeader", protocol_test)

    def test_existing_off_safe_and_strict_layouts_remain_materialized(self) -> None:
        for name, profile in PROFILE_MATRIX.items():
            for variant in THREE_VARIANTS:
                for filename in profile["files"]:
                    with self.subTest(profile=name, variant=variant, file=filename):
                        path = ROOT / profile["directory"] / variant / filename
                        self.assertTrue(path.is_file(), path)

    def test_missing_all_artifact_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copytree(source_path('examples', root=ROOT), root / "examples")
            (root / "examples/apache/all/httpd.conf").unlink()
            errors = all_example_errors(root)
            self.assertTrue(any("apache/all: missing artifact" in error for error in errors))

    def test_missing_response_companion_marker_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copytree(source_path('examples', root=ROOT), root / "examples")
            agent = root / "examples/haproxy/spoe-spop/all/spoa-agent.conf"
            agent.write_text(
                agent.read_text(encoding="utf-8").replace(
                    "response-companion=native-htx", "response-companion=missing"
                ),
                encoding="utf-8",
            )
            errors = all_example_errors(root)
            self.assertTrue(
                any("haproxy-spoe-spop/all" in error and "response-companion" in error for error in errors)
            )

    def test_missing_spop_host_action_mapping_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copytree(source_path('examples', root=ROOT), root / "examples")
            configuration = root / "examples/haproxy/spoe-spop/all/haproxy.cfg"
            configuration.write_text(
                configuration.read_text(encoding="utf-8").replace(
                    "    http-request redirect location %[var(txn.modsec.redirect_url)] code 302 if { var(txn.modsec.action) -m str redirect } { var(txn.modsec.redirect_url) -m found }\n",
                    "",
                ),
                encoding="utf-8",
            )
            errors = all_example_errors(root)
            self.assertTrue(
                any(
                    "haproxy-spoe-spop/all" in error
                    and "http-request redirect location" in error
                    for error in errors
                )
            )

    def test_nonexistent_all_phase4_value_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copytree(source_path('examples', root=ROOT), root / "examples")
            runtime = root / "examples/lighttpd/stock/all/msconnector-runtime.conf"
            runtime.write_text(
                runtime.read_text(encoding="utf-8").replace(
                    "phase4_mode=strict", "phase4_mode=all"
                ),
                encoding="utf-8",
            )
            errors = all_example_errors(root)
            self.assertTrue(
                any("lighttpd-stock/all" in error and "unsupported phase4 value" in error for error in errors)
            )

    def test_wildcard_nginx_binding_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copytree(source_path('examples', root=ROOT), root / "examples")
            configuration = root / "examples/nginx/all/nginx.conf"
            configuration.write_text(
                configuration.read_text(encoding="utf-8").replace(
                    "listen 127.0.0.1:8080;", "listen 80;"
                ),
                encoding="utf-8",
            )
            errors = all_example_errors(root)
            self.assertIn("nginx/all: public default binding is forbidden", errors)

    def test_request_controlled_transaction_identifier_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copytree(source_path('examples', root=ROOT), root / "examples")
            configuration = root / "examples/nginx/all/nginx.conf"
            configuration.write_text(
                configuration.read_text(encoding="utf-8").replace(
                    "# modsecurity_transaction_id $request_id;",
                    "modsecurity_transaction_id $request_uri;",
                ),
                encoding="utf-8",
            )
            errors = all_example_errors(root)
            self.assertIn(
                "nginx/all: request-controlled transaction identifier is forbidden", errors
            )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
