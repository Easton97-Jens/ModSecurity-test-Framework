#!/usr/bin/env python3
"""Common-only build contract scaffold check."""
from modsecurity_test_framework.connector_context import connector_root
from pathlib import Path
ROOT = connector_root()
for rel in ["common/include/msconnector/build_contract.h", "common/src/build_contract.c", "docs/generated/connector-contract.md"]:
    if not (ROOT / rel).exists():
        print(f"missing build contract scaffold: {rel}")
        raise SystemExit(1)
print("build-contracts: common scaffold present; connectors not enforced")
