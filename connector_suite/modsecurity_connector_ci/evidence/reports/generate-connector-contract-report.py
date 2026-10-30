#!/usr/bin/env python3
"""Print a static connector contract skeleton without runtime claims."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import json
from pathlib import Path
ROOT = connector_root()
contract = json.loads((source_path('config/testing/capability-contract.json', root=ROOT)).read_text(encoding="utf-8"))
print(json.dumps({"runtime_verified": False, "capabilities": contract.get("capabilities", {}), "required_tests": contract.get("capabilities", {})}, sort_keys=True))
