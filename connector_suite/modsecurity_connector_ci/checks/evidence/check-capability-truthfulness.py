#!/usr/bin/env python3
"""Check that the capability contract file exists without claiming connector pass status."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import json
ROOT = connector_root()
path = source_path('config/testing/capability-contract.json', root=ROOT)
data = json.loads(path.read_text(encoding="utf-8"))
assert "capabilities" in data
print("capability-truthfulness: contract present; no connector pass claims")
