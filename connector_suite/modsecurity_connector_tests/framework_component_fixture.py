"""Independent component-pin baselines for temporary synchronizer test repos."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
from pathlib import Path
import re


SOURCE_ROOT = connector_root()
HAPROXY_SOURCE_URL = "https://www.haproxy.org/download/3.2/src/haproxy-3.2.23.tar.gz"
HAPROXY_SHA256 = "82d14ef33571e4edeb9197516c0d058a3775fb80541e46afe4377428e461fef0"
LIGHTTPD_SOURCE_URL = "https://download.lighttpd.net/lighttpd/releases-1.4.x/"
LIGHTTPD_DOWNLOAD_URL = LIGHTTPD_SOURCE_URL + "lighttpd-1.4.85.tar.xz"
CRS_REPOSITORY = "https://github.com/coreruleset/coreruleset.git"
CRS_COMMIT = "ab3ccd5fcd691424ba3f320d4040c61417270193"
GUIDE_FIELDS = {
    "MODSECURITY_REF_COMMAND": 'MODSECURITY_REF="v3.0.16"',
    "MODSECURITY_COMMIT_COMMAND": (
        'MODSECURITY_COMMIT="7ea9fefbe0ba409d8733b4d682c8c4c059cd028d"'
    ),
}

# These literal expected inputs belong to the historical offline grammar
# fixture. Keep them independent of live pins and the production synchronizer's
# registry, parser, and renderers so those implementations remain under test.
PYTHON_FIELDS = {
    "ci/provisioning/components/prepare-runtime-components.py": {
        "DEFAULT_HAPROXY_VERSION": "3.2.23",
    },
    "tests/test_prepare_runtime_components.py": {
        "TEST_HAPROXY_LOCKED_VERSION": "3.2.23",
        "TEST_HAPROXY_LOCKED_SOURCE_URL": HAPROXY_SOURCE_URL,
        "TEST_HAPROXY_LOCKED_SHA256": HAPROXY_SHA256,
    },
    "ci/runtime/broker/nginx_root_broker.py": {
        "CRS_APPROVED_REPOSITORY": CRS_REPOSITORY,
        "CRS_RELEASE_TAG": "v4.29.0",
        "CRS_APPROVED_COMMIT": CRS_COMMIT,
    },
    "ci/runtime/broker/protected_nginx_broker_caller.py": {
        "CRS_REPOSITORY": CRS_REPOSITORY,
        "CRS_RELEASE_TAG": "v4.29.0",
        "CRS_COMMIT": CRS_COMMIT,
    },
    "scripts/generate_compiler_guides.py": GUIDE_FIELDS,
    "tests/test_compiler_guides.py": GUIDE_FIELDS,
}
SHELL_FIELDS = {
    "connectors/envoy/config/envoy-ext-proc-versions.env": {
        "ENVOY_RELEASE": "1.39.1",
        "ENVOY_IMAGE": "envoyproxy/envoy:v1.39.1",
    },
    "connectors/lighttpd/lighttpd-version.contract": {
        "LIGHTTPD_SERIES": "1.4",
        "LIGHTTPD_VERSION": "1.4.85",
        "LIGHTTPD_SOURCE_URL": LIGHTTPD_SOURCE_URL,
        "LIGHTTPD_DOWNLOAD_URL": LIGHTTPD_DOWNLOAD_URL,
        "LIGHTTPD_SHA256": (
            "18de51b393bac4a6827879e1a7ff377c169e414bae92cd245091d80fc2601d13"
        ),
    },
}
JSON_FIELDS = (
    (
        "connectors/lighttpd/SOURCE_MAP.json",
        "upstream",
        {
            "repository": LIGHTTPD_SOURCE_URL,
            "series": "1.4",
            "version": "1.4.85",
            "download_url": LIGHTTPD_DOWNLOAD_URL,
        },
    ),
    (
        "connectors/haproxy/htx-overlay/version-contract.json",
        None,
        {
            "version": "3.2.23",
            "source_url": HAPROXY_SOURCE_URL,
            "sha256": HAPROXY_SHA256,
        },
    ),
)


def _render_component_text_fields(rendered):
    for fixtures, python_literals in ((PYTHON_FIELDS, True), (SHELL_FIELDS, False)):
        for relative, fields in fixtures.items():
            for name, value in fields.items():
                pattern = rf"(?m)^({re.escape(name)}[ \t]*=[ \t]*)[^\r\n]*$"
                rhs = json.dumps(value) if python_literals else value
                rendered[relative], count = re.subn(
                    pattern,
                    lambda match: match.group(1) + rhs,
                    rendered[relative],
                )
                if count != 1:
                    raise ValueError(f"{relative}: expected one component slot for {name}")


def _render_component_json_fields(original, rendered):
    for relative, parent, fields in JSON_FIELDS:
        payload = json.loads(original[relative])
        if not isinstance(payload, dict):
            raise ValueError(f"{relative}: expected a JSON object")
        target = payload if parent is None else payload.get(parent)
        if not isinstance(target, dict) or any(
            not isinstance(target.get(name), str) for name in fields
        ):
            raise ValueError(f"{relative}: missing or malformed component slots")
        target.update(fields)
        rendered[relative] = json.dumps(payload, indent=2) + "\n"


def set_framework_component_fixture(root: Path) -> None:
    """Reset copied component pins without using the implementation under test."""
    if root.resolve() == SOURCE_ROOT:
        raise ValueError("Framework component fixtures must not modify the source checkout")

    relative_paths = (
        *PYTHON_FIELDS,
        *SHELL_FIELDS,
        *(relative for relative, _parent, _fields in JSON_FIELDS),
    )
    # Legacy grammar fixtures may retain historical Framework-owned source
    # slots, but only inside this explicitly isolated test tree. Product
    # synchronizers must leave them untouched after the ownership migration.
    for relative in relative_paths:
        destination = root / relative
        if not destination.exists():
            original_source = source_path(relative, root=SOURCE_ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(original_source.read_bytes())
    original = {
        relative: (root / relative).read_bytes().decode("utf-8")
        for relative in relative_paths
    }
    rendered = dict(original)
    _render_component_text_fields(rendered)

    _render_component_json_fields(original, rendered)

    # Check every independent fixture slot before writing any copied file.
    for relative, text in rendered.items():
        if text != original[relative]:
            (root / relative).write_bytes(text.encode("utf-8"))
