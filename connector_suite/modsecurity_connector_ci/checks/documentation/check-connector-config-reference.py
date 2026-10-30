#!/usr/bin/env python3
"""Validate parser-backed connector configuration documentation.

The checker intentionally uses the same connector-specific extractors as the
generator: Apache ``command_rec``, NGINX ``ngx_command_t``, HAProxy's native
HTX keyword parser, Envoy YAML/Go JSON/CLI contracts, Traefik YAML/plugin
configuration, lighttpd ``config_plugin_values_init``, the Common Runtime
branch parser, and directives actually used by example rule files.  It is not
a free-text grep check.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root
from modsecurity_test_framework.connector_context import load_source

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path


ROOT = connector_root()


from modsecurity_connector_ci.checks.documentation.connector_config_reference import CONNECTORS, build_inventory, documented_path, german_translation_errors, inventory_json, rendered_files
_MATRIX_MODULE = load_source(Path(__file__).resolve().parent / 'check-logical-connector-example-matrix.py')
logical_connector_example_errors = _MATRIX_MODULE.logical_connector_example_errors


REQUIRED_INVENTORY_FIELDS = frozenset({
    "connector",
    "name",
    "configuration_layer",
    "source_file",
    "source_symbol",
    "implemented",
    "selected_integration_mode",
    "documented_in",
    "german_documented_in",
    "syntax",
    "value_type",
    "allowed_values",
    "default",
    "default_source",
    "required",
    "contexts",
    "inheritance",
    "merge_behavior",
    "validation",
    "phase_relevance",
    "security_relevance",
    "runtime_effect",
    "example_file",
    "compatibility_only",
    "deprecated",
    "description",
})

PROFILE_README = "README.md"
DETECTION_ONLY_RULES = "rules/detection-only.conf"
ENGINE_OFF_RULES = "rules/engine-off.conf"
PROFILE_REQUIREMENTS = {
    "apache": ("off/httpd.conf", "safe/httpd.conf", PROFILE_README, "detection-only/httpd.conf", "disabled/httpd.conf", DETECTION_ONLY_RULES, ENGINE_OFF_RULES),
    "nginx": ("off/nginx.conf", "safe/nginx.conf", "strict/nginx.conf", "detection-only/nginx.conf", "disabled/nginx.conf", DETECTION_ONLY_RULES, ENGINE_OFF_RULES),
    "haproxy": ("off/haproxy-htx.cfg", "safe/haproxy-htx.cfg", PROFILE_README, "detection-only/haproxy-htx.cfg", "disabled/haproxy-htx.cfg", DETECTION_ONLY_RULES, ENGINE_OFF_RULES),
    "envoy": ("off/envoy-ext-proc-streaming.yaml.in", "off/envoy-ext-proc-service.json", "off/msconnector-runtime.conf", "safe/envoy-ext-proc-streaming.yaml.in", "safe/envoy-ext-proc-service.json", PROFILE_README, "detection-only/msconnector-runtime.conf", "disabled/msconnector-runtime.conf", DETECTION_ONLY_RULES, ENGINE_OFF_RULES),
    "traefik": ("off/traefik-static.yaml", "off/traefik-dynamic.yaml", "off/traefik-engine-service.conf", "safe/traefik-dynamic.yaml", "safe/traefik-engine-service.conf", PROFILE_README, "detection-only/traefik-engine-service.conf", "disabled/traefik-engine-service.conf", DETECTION_ONLY_RULES, ENGINE_OFF_RULES),
    "lighttpd": ("off/lighttpd.conf", "off/msconnector-runtime.conf", "safe/lighttpd-http1-identity.conf", "safe/msconnector-runtime.conf", PROFILE_README, "detection-only/msconnector-runtime.conf", "disabled/lighttpd.conf", DETECTION_ONLY_RULES, ENGINE_OFF_RULES),
}


def option_sections(text: str) -> set[str]:
    result: set[str] = set()
    for line in text.splitlines():
        if line.startswith("## `") and line.endswith("`"):
            result.add(line[4:-1])
    return result


def required_top_table(text: str) -> bool:
    return "| Option | Layer | Type | Required | Default | Context | Short description |" in text


def profile_file_errors(root: Path) -> list[str]:
    errors: list[str] = []
    for connector, files in PROFILE_REQUIREMENTS.items():
        base = root / "examples" / connector
        for relative in files:
            if not (base / relative).is_file():
                errors.append(f"examples/{connector}/{relative}: required profile file is missing")
    return errors


def profile_rule_errors(root: Path) -> list[str]:
    errors: list[str] = []
    for connector in PROFILE_REQUIREMENTS:
        base = root / "examples" / connector
        detection = base / DETECTION_ONLY_RULES
        disabled = base / ENGINE_OFF_RULES
        if detection.is_file() and "SecRuleEngine DetectionOnly" not in detection.read_text(encoding="utf-8"):
            errors.append(f"{detection.relative_to(root)}: missing SecRuleEngine DetectionOnly")
        if disabled.is_file() and "SecRuleEngine Off" not in disabled.read_text(encoding="utf-8"):
            errors.append(f"{disabled.relative_to(root)}: missing SecRuleEngine Off")
    return errors


def profile_readme_errors(root: Path) -> list[str]:
    errors: list[str] = []
    for connector in PROFILE_REQUIREMENTS:
        strict_reference = root / "examples" / connector / PROFILE_README
        if strict_reference.is_file() and 'id="strict-profile-boundary"' not in strict_reference.read_text(encoding="utf-8"):
            errors.append(f"{strict_reference.relative_to(root)}: missing consolidated strict-profile-boundary")
    return errors


def profile_local_path_errors(root: Path) -> list[str]:
    errors: list[str] = []
    local_path = re.compile(r"/(?:root/(?:git|conecter)|srv/modsecurity-work)(?:/|\b)")
    for path in (root / "examples").rglob("*"):
        if path.is_file() and path.suffix in {".md", ".conf", ".cfg", ".yaml", ".in", ".json"}:
            if local_path.search(path.read_text(encoding="utf-8", errors="replace")):
                errors.append(f"{path.relative_to(root)}: contains a local development path")
    return errors


def profile_layout_errors(root: Path) -> list[str]:
    """Check the committed off/safe/strict/detection/disabled examples."""
    return [
        *profile_file_errors(root),
        *profile_rule_errors(root),
        *profile_readme_errors(root),
        *profile_local_path_errors(root),
    ]


def german_prose_errors(text: str) -> list[str]:
    """Catch stale English renderer boilerplate outside explicit source blocks.

    YAML fallback sections deliberately retain original source metadata in a
    ``text`` fence so concrete protocol/default information is not lost.  The
    surrounding German explanation must nevertheless not regress to an old
    English heading, table label, code comment, or combination result.
    """
    markers = (
        "## Scope and source of truth",
        "Compatibility-Einträge",
        "[Common Runtime configuration]",
        "[ModSecurity Engine directives]",
        "[Rule examples]",
        "| Type | Allowed values | Required |",
        "| Profile | File | Status |",
        "| Connector | Engine | Request body | Response body | Result |",
        "No connector transaction; engine setting is not reached.",
        "Repository-Targets:",
        "See [",
        "# Enforce an eligible pre-commit deny.",
        "# Match and log without a disruptive action.",
        "# Do not evaluate rules after they are loaded.",
        "Source:",
        "Merge:",
    )
    errors: list[str] = []
    in_fence = False
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for marker in markers:
            if marker in line:
                errors.append(f"line {number}: untranslated renderer marker {marker!r}")
    return errors


def inventory_validation_errors(inventory: list[dict[str, object]]) -> tuple[list[str], dict[str, set[str]]]:
    errors: list[str] = []
    names_by_doc: dict[str, set[str]] = {}
    for option in inventory:
        missing_fields = REQUIRED_INVENTORY_FIELDS - option.keys()
        if missing_fields:
            errors.append(
                f"{option.get('connector', '<unknown>')}:{option.get('name', '<unknown>')}: "
                f"inventory fields missing: {', '.join(sorted(missing_fields))}"
            )
            continue
        names_by_doc.setdefault(option["documented_in"], set()).add(option["name"])
        names_by_doc.setdefault(option["german_documented_in"], set()).add(option["name"])
        if option["compatibility_only"] and option["configuration_layer"] != "compatibility":
            errors.append(f"{option['connector']}:{option['name']}: compatibility option has wrong layer")
        if option["value_type"] == "historical configuration" and option["implemented"]:
            errors.append(f"{option['connector']}:{option['name']}: historical material must not be marked implemented")
    return errors, names_by_doc


def rendered_reference_errors(
    root: Path,
    rendered: dict[Path, str],
    names_by_doc: dict[str, set[str]],
) -> list[str]:
    errors: list[str] = []
    for path, expected in rendered.items():
        relative = path.relative_to(root).as_posix()
        if not path.is_file():
            errors.append(f"{relative}: missing generated reference")
            continue
        actual = path.read_text(encoding="utf-8")
        if actual != expected:
            errors.append(f"{relative}: generated content differs from source-backed renderer")
        if relative.endswith(".de.md"):
            errors.extend(f"{relative}: {error}" for error in german_prose_errors(actual))
        if path.name.startswith("configuration-reference") or path.name in {"common-connector-configuration.md", "common-connector-configuration.de.md", "modsecurity-directives.md", "modsecurity-directives.de.md"}:
            if not required_top_table(actual):
                errors.append(f"{relative}: missing required top inventory table")
        expected_names = names_by_doc.get(relative, set())
        missing = expected_names - option_sections(actual)
        if missing:
            errors.append(f"{relative}: missing option sections: {', '.join(sorted(missing))}")
    return errors


def language_parity_errors(root: Path) -> list[str]:
    errors: list[str] = []
    # Technical bilingual parity is checked on the rendered structured content:
    # every documented option section and all source-derived values are emitted
    # from the same inventory in both companions.
    for connector in CONNECTORS:
        english = root / documented_path(connector, False)
        german = root / documented_path(connector, True)
        if english.is_file() and german.is_file():
            if option_sections(english.read_text(encoding="utf-8")) != option_sections(german.read_text(encoding="utf-8")):
                errors.append(f"{connector}: English/German option-section parity differs")
    for connector, filename in (("common", "common-connector-configuration"), ("engine", "modsecurity-directives")):
        english = root / f"examples/common/{filename}.md"
        german = root / f"examples/common/{filename}.de.md"
        if english.is_file() and german.is_file() and option_sections(english.read_text(encoding="utf-8")) != option_sections(german.read_text(encoding="utf-8")):
            errors.append(f"{connector}: English/German option-section parity differs")
    return errors


def inventory_json_schema_errors(expected_json: str) -> list[str]:
    errors: list[str] = []
    # The JSON remains easy to consume by external tooling, not just this
    # checker.  Reparse it after exact-content validation for schema sanity.
    try:
        payload = json.loads(expected_json)
        if payload.get("schema_version") != 1 or not isinstance(payload.get("options"), list):
            errors.append("inventory JSON schema_version/options shape is invalid")
    except json.JSONDecodeError as error:
        errors.append(f"inventory JSON failed to parse: {error}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    try:
        inventory = build_inventory(root)
        rendered = rendered_files(root)
    except (OSError, ValueError) as error:
        print(f"connector config reference: FAIL: {error}", file=sys.stderr)
        return 2

    expected_json = inventory_json(root)
    inventory_path = root / "reports/connector-configuration-inventory.json"
    errors = profile_layout_errors(root)
    errors.extend(logical_connector_example_errors(root))
    errors.extend(german_translation_errors(inventory))
    inventory_errors, names_by_doc = inventory_validation_errors(inventory)
    errors.extend(inventory_errors)
    errors.extend(rendered_reference_errors(root, rendered, names_by_doc))
    errors.extend(language_parity_errors(root))
    errors.extend(inventory_json_schema_errors(expected_json))
    if not inventory_path.is_file() or inventory_path.read_text(encoding="utf-8") != expected_json:
        errors.append("reports/connector-configuration-inventory.json is stale or missing")
    if errors:
        print("connector config reference: FAIL", file=sys.stderr)
        print("\n".join(sorted(errors)), file=sys.stderr)
        return 1
    counts = {connector: sum(option["connector"] == connector for option in inventory) for connector in (*CONNECTORS, "common", "engine")}
    print("connector config reference: PASS " + ", ".join(f"{name}={count}" for name, count in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
