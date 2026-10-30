#!/usr/bin/env python3
"""Verify build/link targets are separate from self-tests and runtime smokes."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import re
import sys


ROOT = connector_root()
PRODUCT_MAKEFILE = source_path("Makefile", root=ROOT).read_text(encoding="utf-8")
MAKEFILE = (test_root() / "connector_suite/connector.mk").read_text(encoding="utf-8")
errors: list[str] = []


def target_lines(source: str, target: str) -> list[str]:
    matches = list(re.finditer(
        rf"^{re.escape(target)}[ \t]*:[^\n]*\n(?:\t[^\n]*(?:\n|$))*",
        source, flags=re.MULTILINE,
    ))
    return matches[0].group().splitlines() if len(matches) == 1 else []


forwarder = target_lines(PRODUCT_MAKEFILE, "%")
if forwarder != [
        "%: FORCE",
        '\t@test -f "$(TEST_ROOT)/connector_suite/connector.mk" || { echo "BLOCKED: pinned Framework connector suite is missing" >&2; exit 77; }',
        '\t@$(MAKE) --no-print-directory -f "$(TEST_ROOT)/connector_suite/connector.mk" -C "$(CONNECTOR_ROOT)" "$@"']:
    errors.append("Product Makefile must forward targets to the explicit pinned Framework connector.mk")
if target_lines(PRODUCT_MAKEFILE, "framework-native-selftest") != [
        "framework-native-selftest:",
        '\t@$(PYTHON) -P "$(TEST_ROOT)/connector_native_tests/invoke.py"']:
    errors.append("Product native self-test entry must delegate to the explicit Framework adapter")

for target in (
    "build-envoy-connector",
    "build-traefik-connector",
    "build-lighttpd-connector",
    "build-lighttpd-bridge",
    "build-remaining-connectors",
):
    if re.search(rf"^{re.escape(target)}\s*:", MAKEFILE, flags=re.MULTILINE) is None:
        errors.append(f"Framework connector.mk missing {target}")

build_scripts = (
    "connectors/envoy/build/build_connector.sh",
    "connectors/traefik/build/build-connector.sh",
    "connectors/lighttpd/build/build_module.sh",
    "connectors/lighttpd/build/bridge_starter.sh",
)
for relative in build_scripts:
    path = ROOT / relative
    if not path.is_file():
        errors.append(f"build script missing: {relative}")
        continue
    content = path.read_text(encoding="utf-8", errors="replace")
    if "--self-test" in content:
        errors.append(f"build script runs or references a self-test: {relative}")
    if not any(flag in content for flag in ("-std=c17", '-std="$MSCONNECTOR_C_STD"')):
        errors.append(f"C17 build policy missing: {relative}")
    if "-Werror" not in content:
        errors.append(f"warnings-as-errors missing: {relative}")

lighttpd_make = (source_path('connectors/lighttpd/Makefile', root=ROOT)).read_text(encoding="utf-8")
if target_lines(lighttpd_make, "self-test-lighttpd-bridge") != [
        "self-test-lighttpd-bridge:",
        "\t$(MAKE) -C ../.. framework-native-selftest NATIVE_TEST_TARGET=lighttpd-bridge"]:
    errors.append("lighttpd bridge self-test must remain a distinct Framework-native delegation")
if (re.search(r"^self-test-lighttpd-bridge[ \t]*:[ \t]*build-lighttpd-bridge[ \t]*$",
              MAKEFILE, flags=re.MULTILINE) is None):
    errors.append("Framework lighttpd self-test must retain its separate bridge build prerequisite")
bridge_build = (source_path('connectors/lighttpd/build/bridge_starter.sh', root=ROOT)).read_text(
    encoding="utf-8", errors="replace"
)
if "self-test.txt" in bridge_build or "--self-test" in bridge_build:
    errors.append("lighttpd bridge build still executes its self-test")

if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
print("remaining connectors build wiring: ok")
