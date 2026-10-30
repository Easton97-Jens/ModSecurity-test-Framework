"""Independent Framework SHA fixtures for temporary test repositories."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
from pathlib import Path
import re

SOURCE_ROOT = connector_root()
LOCK_PATH = "ci/tooling/project-versions.lock.json"


def set_framework_sha_fixture(root: Path, framework_sha: str) -> None:
    """Reset copied lock/integration identities independently of the projector."""
    if root.resolve() == SOURCE_ROOT or (root / ".git").exists():
        raise ValueError("Framework SHA fixtures must not modify the source checkout")
    if re.fullmatch(r"[0-9a-f]{40}", framework_sha) is None:
        raise ValueError("test Framework SHA must be 40 lowercase hexadecimal characters")
    path = root / LOCK_PATH
    if path.is_symlink():
        raise ValueError("copied revision lock must not be a symlink")
    original = path.read_bytes()
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate copied revision lock field")
            result[key] = value
        return result
    payload = json.loads(original, object_pairs_hook=unique_object)
    if (not isinstance(payload, dict)
        or set(payload) != {"schema_version", "framework_sha", "mrts_sha", "python_version", "go_version"}
        or type(payload["schema_version"]) is not int or payload["schema_version"] != 1
        or any(not isinstance(payload[key], str)
               or re.fullmatch(r"[0-9a-f]{40}", payload[key]) is None
               for key in ("framework_sha", "mrts_sha"))
        or not isinstance(payload["python_version"], str)
        or re.fullmatch(r"3\.15\.(?:0|[1-9][0-9]*)", payload["python_version"]) is None
        or len(payload["python_version"]) > 32
        or not isinstance(payload["go_version"], str)
        or re.fullmatch(r"[1-9][0-9]*\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", payload["go_version"]) is None
        or len(payload["go_version"]) > 32):
        raise ValueError("invalid copied revision lock schema")
    if payload["framework_sha"] != framework_sha:
        payload["framework_sha"] = framework_sha
        path.write_bytes((json.dumps(payload, indent=2) + "\n").encode("utf-8"))
    # A copied migration checkout may contain temporary pin markers. They are
    # fixture inputs only: the product projector accepts exact SHA-40 values.
    patterns = (
        r"(?m)^([ \t]*(?:-[ \t]+)?uses:[ \t]+Easton97-Jens/ModSecurity-test-Framework/[^\s@]+@)[^\s#]+",
        r"(?m)^([ \t]*framework-revision:[ \t]+)(?!\$\{\{)[^\s#]+",
    )
    for workflow in sorted((root / ".github/workflows").glob("*.yml")):
        if workflow.is_symlink():
            raise ValueError("copied workflow must not be a symlink")
        original_workflow = workflow.read_text()
        rendered = original_workflow
        for pattern in patterns:
            rendered = re.sub(pattern, lambda match: match[1] + framework_sha, rendered)
        if rendered != original_workflow:
            workflow.write_text(rendered)
