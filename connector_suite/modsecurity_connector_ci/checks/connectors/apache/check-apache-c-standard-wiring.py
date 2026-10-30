#!/usr/bin/env python3
"""Check Makefile and script wiring for Apache C-standard smoke checks."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import sys

ROOT = connector_root()
MAKEFILE = test_root() / "connector_suite" / "connector.mk"
SCRIPT = source_path('ci/checks/connectors/apache/check-apache-c-standards.sh', root=ROOT)

ok = True


def fail(message: str) -> None:
    global ok
    print(f"FAIL: {message}")
    ok = False


def pass_(message: str) -> None:
    print(f"PASS: {message}")


def makefile_has_target(text: str, target: str) -> bool:
    prefix = f"{target}:"
    return any(line.startswith(prefix) for line in text.splitlines())


def makefile_target_body(text: str, target: str) -> list[str]:
    lines = text.splitlines()
    body: list[str] = []
    in_target = False
    for line in lines:
        if line.startswith(f"{target}:"):
            in_target = True
            continue
        if in_target and line and not line.startswith("\t") and not line.startswith(" "):
            break
        if in_target:
            body.append(line)
    return body


if not SCRIPT.exists():
    fail("ci/checks/connectors/apache/check-apache-c-standards.sh exists")
    script_text = ""
else:
    pass_("ci/checks/connectors/apache/check-apache-c-standards.sh exists")
    script_text = SCRIPT.read_text(encoding="utf-8")

make_text = MAKEFILE.read_text(encoding="utf-8")
for target in (
    "check-apache-c17",
    "check-apache-c17-lint",
    "check-apache-c23",
    "check-apache-future-c",
    "check-apache-c-standards",
    "check-apache-c20",
    "check-apache-c26",
):
    if makefile_has_target(make_text, target):
        pass_(f"Makefile contains {target}")
    else:
        fail(f"Makefile contains {target}")

lint_body = makefile_target_body(make_text, "lint")
if any("$(MAKE) check-apache-c17-lint" in line for line in lint_body):
    pass_("lint invokes check-apache-c17-lint")
else:
    fail("lint invokes check-apache-c17-lint")

if "-Wno-error" in script_text:
    fail("Apache C standards check must not use -Wno-error")
else:
    pass_("Apache C standards check does not use -Wno-error")

required_script_terms = {
    "mandatory C17 flags": "-std=c17 -Wall -Wextra -Werror",
    "optional c23 profile": "--profile \"$profile\"",
    "exit 77 blocked path": "exit 77",
    "framework common import": "FRAMEWORK_COMMON",
    "central APXS provision helper": "require_or_provision_apxs",
    "central command blocker helper": "require_command_or_blocked",
    "central libmodsecurity header provision helper": "modsecurity_include_flags_or_provision",
    "shared intervention source": "common/src/intervention.c",
    "optional skip wording": "SKIPPED: optional Apache C23 check",
    "future-C skip wording": "SKIPPED: optional Apache future-C check",
}
for label, term in required_script_terms.items():
    if term in script_text:
        pass_(label)
    else:
        fail(label)

if not ok:
    sys.exit(1)
print("apache-c-standard-wiring: pass")
