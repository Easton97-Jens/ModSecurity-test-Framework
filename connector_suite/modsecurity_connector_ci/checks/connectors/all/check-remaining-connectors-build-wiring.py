#!/usr/bin/env python3
"""Verify build/link targets are separate from self-tests and runtime smokes."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import re
import sys


ROOT = connector_root()
MAKEFILE = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
errors: list[str] = []

for target in (
    "build-envoy-connector",
    "build-traefik-connector",
    "build-lighttpd-connector",
    "build-lighttpd-bridge",
    "build-remaining-connectors",
):
    if re.search(rf"^{re.escape(target)}\s*:", MAKEFILE, flags=re.MULTILINE) is None:
        errors.append(f"root Makefile missing {target}")

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
if "self-test-lighttpd-bridge: build-lighttpd-bridge" not in lighttpd_make:
    errors.append("lighttpd bridge self-test is not a distinct target")
bridge_build = (source_path('connectors/lighttpd/build/bridge_starter.sh', root=ROOT)).read_text(
    encoding="utf-8", errors="replace"
)
if "self-test.txt" in bridge_build or "--self-test" in bridge_build:
    errors.append("lighttpd bridge build still executes its self-test")

if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
print("remaining connectors build wiring: ok")
