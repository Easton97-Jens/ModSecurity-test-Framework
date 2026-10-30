#!/usr/bin/env python3
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path
from pathlib import Path
import re
import subprocess
import sys

from modsecurity_connector_ci.lib.active_test_inventory import load_inventory, select_executions

ROOT = connector_root()

COMMON_APIS = ["resource_limits", "memory", "flow_guard", "integrity_event", "dos_guard"]
EVENT_JSON_SOURCES = [
    "common/src/event.c",
    "common/src/event_jsonl.c",
    "common/src/integrity_event.c",
    "common/src/decision.c",
]
FORBIDDEN_PAYLOAD_FIELDS = [
    "request_body",
    "response_body",
    "body_payload",
    "raw_body",
    "payload",
    "body",
    "request_payload",
    "response_payload",
]
FORBIDDEN_COMMON_TOKENS = [
    "#include <httpd",
    "#include <ngx_",
    "#include <haproxy",
]
FORBIDDEN_COMMON_CALLS = ("strcpy", "strcat", "sprintf", "gets")
MODSECURITY_INCLUDE_PATTERN = re.compile(
    r'^\s*#\s*include\s*[<"]modsecurity/', re.MULTILINE
)
ALLOWED_MODSECURITY_INCLUDE_ROOT = Path("common/runtime")
FORBIDDEN_CLAIM_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"connector is protected",
        r"runtime secure",
        r"production[- ]ready",
        r"security[- ]verified",
        r"verified for (nginx|apache|haproxy|envoy|lighttpd|traefik)",
        r"response_body verified",
        r"crs verified",
        r"full matrix verified",
    ]
]
FORBIDDEN_HASH_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"secure hash",
        r"cryptographic hash",
        r"tamper-proof",
        r"cannot be manipulated",
    ]
]

errors = []

for name in COMMON_APIS:
    for directory, suffix in [("common/include/msconnector", ".h"), ("common/src", ".c")]:
        path = ROOT / directory / f"{name}{suffix}"
        if not path.is_file():
            errors.append(f"missing {path.relative_to(ROOT)}")
    src = source_path('common/src', root=ROOT) / f"{name}.c"
    if src.is_file() and f'#include "msconnector/{name}.h"' not in src.read_text():
        errors.append(f"{src.relative_to(ROOT)} missing matching header include")

common_files = sorted((source_path('common', root=ROOT)).rglob("*.c"))
common_files += sorted((source_path('common', root=ROOT)).rglob("*.h"))
common_files += [source_path(f"common/{directory}/{name}{suffix}", root=ROOT)
                 for directory, suffix in (("src", ".c"), ("include/msconnector", ".h"))
                 for name in ("test_result", "test_result_json")]
common_text = "\n".join(path.read_text(errors="ignore") for path in common_files)
for token in FORBIDDEN_COMMON_TOKENS:
    if token in common_text:
        errors.append(f"forbidden common token {token}")
for function_name in FORBIDDEN_COMMON_CALLS:
    # Match an actual function identifier, not a suffix such as fgets().
    if re.search(rf"(?<![A-Za-z0-9_]){re.escape(function_name)}\s*\(", common_text):
        errors.append(f"forbidden common token {function_name}(")
for path in common_files:
    relative = path.relative_to(ROOT)
    if not MODSECURITY_INCLUDE_PATTERN.search(path.read_text(errors="ignore")):
        continue
    if ALLOWED_MODSECURITY_INCLUDE_ROOT not in relative.parents:
        errors.append(
            f"forbidden ModSecurity host API include outside "
            f"{ALLOWED_MODSECURITY_INCLUDE_ROOT}: {relative}"
        )

for source in EVENT_JSON_SOURCES:
    path = ROOT / source
    if not path.is_file():
        errors.append(f"missing event/decision JSON source {source}")
        continue
    text = path.read_text(errors="ignore")
    for field in FORBIDDEN_PAYLOAD_FIELDS:
        quoted = f'"{field}"'
        escaped = f'\\"{field}\\"'
        if quoted in text or escaped in text:
            errors.append(f"{source} writes forbidden body/payload JSON field {field}")

integrity_api = (source_path('common/include/msconnector/integrity_event.h', root=ROOT)).read_text(errors="ignore") + (source_path('common/src/integrity_event.c', root=ROOT)).read_text(errors="ignore")
if "non_crypto" not in integrity_api:
    errors.append("integrity API must name non-cryptographic hash helpers with non_crypto")

doc_text = "\n".join(
    path.read_text(errors="ignore")
    for path in (source_path('docs/architecture.md', root=ROOT), source_path('docs/architecture.de.md', root=ROOT))
    if path.is_file()
)
if "non_crypto" not in doc_text or "CI" not in doc_text or "Smoke" not in doc_text and "smoke" not in doc_text:
    errors.append("common security docs must state non_crypto CI/smoke scope")
for pattern in FORBIDDEN_HASH_PATTERNS:
    if pattern.search(integrity_api + "\n" + doc_text):
        errors.append(f"forbidden hash/integrity claim: {pattern.pattern}")

claim_paths = list(common_files)
claim_paths += [
    source_path('docs/architecture.md', root=ROOT),
    source_path('docs/architecture.de.md', root=ROOT),
    source_path('ci/checks/common/check-common-flow-integrity.py', root=ROOT),
    source_path('ci/checks/common/check-common-memory-safety.sh', root=ROOT),
    source_path('ci/checks/common/check-common-helpers.sh', root=ROOT),
]
changed_scope_text = "\n".join(
    path.read_text(errors="ignore")
    for path in claim_paths
    if path.is_file()
)
for pattern in FORBIDDEN_CLAIM_PATTERNS:
    if pattern.search(changed_scope_text):
        errors.append(f"forbidden runtime/production claim: {pattern.pattern}")

dos = (source_path('common/src/dos_guard.c', root=ROOT)).read_text(errors="ignore")
if "msconnector_resource_limits" not in dos:
    errors.append("DoS guard does not use resource limits")
if "enum msconnector_phase" not in (source_path('common/include/msconnector/flow_guard.h', root=ROOT)).read_text(errors="ignore"):
    errors.append("flow guard lacks enum msconnector_phase")

makefile = (test_root() / 'connector_suite/connector.mk').read_text(errors="ignore")
for target in ["check-common-security-contract", "check-common-memory-safety", "check-common-flow-integrity"]:
    # Ask Make to resolve its actual default conditional recipe. A source
    # regex requiring a tab immediately after ':' rejects valid ifeq blocks.
    recipe = subprocess.run(["make", "--no-print-directory", "-n", target, "ON_DEMAND_TESTS=0"],
                            cwd=ROOT, capture_output=True, text=True, check=False)
    if recipe.returncode or not recipe.stdout.strip():
        errors.append(f"Makefile target {target} is not executable")
    if target == "check-common-memory-safety" and not any(
            " -P -m modsecurity_test_framework.connector " in line
            and line.endswith(" --group memory-safety")
            for line in recipe.stdout.splitlines()):
        errors.append("default memory safety target must dispatch the authoritative memory-safety group")
    lint_block = makefile[makefile.find("lint: check-framework") : makefile.find("summary: check-framework")]
    if f"$(MAKE) {target}" not in lint_block:
        errors.append(f"lint does not run {target}")
if not re.search(r"^quick-check codex-check: lint", makefile, re.MULTILINE):
    errors.append("quick-check/codex-check must depend on lint")

try:
    memory = select_executions(load_inventory(ROOT), ("memory-safety",))
    expected = {"wipe-free", "limit-rejection", "null-zero", "idempotent-null-free"}
    if (len(memory) != 1 or memory[0]["selector"] != {
            "kind": "native", "script": "ci/checks/common/check-common-memory-safety.sh", "args": []}
            or {case["id"].rsplit(".", 1)[-1] for case in memory[0]["cases"]} != expected):
        errors.append("memory-safety group must retain all four actual native ownership behaviors")
except (OSError, ValueError) as error:
    errors.append("invalid memory-safety inventory contract: " + str(error))

if errors:
    print("\n".join(errors))
    sys.exit(1)
print("common security contract: ok")
