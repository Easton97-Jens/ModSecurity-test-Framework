#!/usr/bin/env python3
"""Common-only origin governance scaffold check."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
ROOT = connector_root()
required = [
    source_path('common/include/msconnector/origin_governance.h', root=ROOT),
    source_path('common/src/origin_governance.c', root=ROOT),
    source_path('docs/generated/origin-governance.md', root=ROOT),
    source_path('docs/generated/origin-governance.de.md', root=ROOT),
]
missing = [str(p.relative_to(ROOT)) for p in required if not p.exists()]
if missing:
    for item in missing: print(f"missing origin governance scaffold: {item}")
    raise SystemExit(1)
for path in sorted((source_path('connectors', root=ROOT)).glob("*")):
    if path.is_dir(): print(f"INFO: {path.relative_to(ROOT)} not enforced; common origin governance not yet adopted")
print("origin-governance: common scaffold present")
