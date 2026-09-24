#!/usr/bin/env python3
from pathlib import Path
import sys, tomllib

root = Path(__file__).resolve().parents[2]
errors = []

agents = root / "AGENTS.md"
if not agents.is_file():
    errors.append("missing AGENTS.md")
else:
    text = agents.read_text(encoding="utf-8")
    if "codex-control-plane-routing:framework" not in text:
        errors.append("missing framework routing marker")
    if "/root/.agents/skills/goal-driven-execution/SKILL.md" not in text:
        errors.append("missing global skill path")
    if "/root/.codex/RTK.md" not in text:
        errors.append("missing RTK instruction path")

for rel in [
    ".codex/config.toml",
    ".codex/inheritance-manifest.toml",
    ".codex/context/index.md",
    ".codex/context/repository-boundaries.md",
    ".codex/context/testing-and-evidence.md",
    ".codex/context/security-policy.md",
    ".codex/context/delivery-policy.md",
    ".codex/context/mrts-boundary-policy.md",
    ".codex/context/python-policy.md",
    ".codex/context/documentation-and-traceability.md",
    ".codex/context/cleanup-and-restoration.md",
    ".codex/context/definition-of-done.md",
]:
    if not (root / rel).is_file():
        errors.append(f"missing {rel}")

cfg_path = root / ".codex/config.toml"
if cfg_path.is_file():
    cfg = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    env = cfg.get("shell_environment_policy", {}).get("set", {})
    py = env.get("PYTHON", "")
    venv = env.get("VIRTUAL_ENV", "")
    if "/root/git/ModSecurity-conector/.venv" in (py, venv):
        errors.append("Framework config still reuses Parent .venv")
    roots = cfg.get("sandbox_workspace_write", {}).get("writable_roots", [])
    if "/root/git/ModSecurity-conector/.venv" in roots:
        errors.append("Parent .venv remains a Framework writable root")

if errors:
    print("Framework V3.2 structure: FAILED")
    for e in errors:
        print(f"ERROR: {e}")
    sys.exit(1)
print("Framework V3.2 structure: OK")
