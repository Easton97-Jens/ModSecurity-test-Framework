#!/usr/bin/env python3
"""Fresh parser observations for historical NGINX fixture defects; no traffic."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ARTIFACT_PATH_PATTERN = r"/[A-Za-z0-9_./-]+"
SCOPE_FILENAME = "scope.txt"
SEALED_INPUT_ROOTS = (Path("/mnt/fixtures"), Path("/mnt/artifacts"))


def artifact_root():
    """Require the operator's existing private project artifact directory."""
    value = os.environ.get("CODEX_TEMP_ROOT")
    if not value:
        raise ValueError("CODEX_TEMP_ROOT must name a protected project directory")
    root = Path(value)
    if not root.is_absolute() or root.parent == root or root != root.resolve() or not root.is_dir():
        raise ValueError("canonical existing CODEX_TEMP_ROOT required")
    metadata = root.lstat()
    if metadata.st_uid not in (0, os.geteuid()) or metadata.st_mode & 0o022:
        raise ValueError("CODEX_TEMP_ROOT must be operator-owned and protected")
    return root


def shared_transit(ancestor, existing, project_root, metadata):
    return (not ancestor.is_relative_to(project_root) and ancestor != existing
            and stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
            and metadata.st_mode & stat.S_ISVTX)


def validate_artifact_ancestry(existing, project_root):
    for ancestor in (existing, *existing.parents):
        metadata = ancestor.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid not in (0, os.geteuid()):
            raise ValueError("operator-owned nonsymlink artifact ancestry required")
        if metadata.st_mode & 0o022 and not shared_transit(ancestor, existing, project_root, metadata):
            raise ValueError("artifact ancestry must not be group/world writable")


def trusted_path(value, *, directory=False, fresh=False):
    """Accept canonical, operator-owned paths outside writable shared areas."""
    match = re.fullmatch(ARTIFACT_PATH_PATTERN, str(value))
    if match is None:
        raise ValueError("absolute configuration-safe artifact path required")
    path = Path(match.group(0))
    project_root = artifact_root()
    roots = (project_root,) if fresh else (project_root, *SEALED_INPUT_ROOTS)
    if path != path.resolve() or not any(path.is_relative_to(root) for root in roots):
        raise ValueError("canonical task-owned artifact path required")
    existing = path.parent if fresh else path
    validate_artifact_ancestry(existing, project_root)
    if fresh:
        if path.exists() or path.is_symlink():
            raise ValueError("fresh task-owned output required")
    elif directory:
        if not path.is_dir():
            raise ValueError("artifact directory required")
    elif not path.is_file():
        raise ValueError("regular artifact file required")
    return path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ("nginx-binary", "module", "library-dir", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    args.output = trusted_path(args.output, fresh=True)
    args.nginx_binary = trusted_path(args.nginx_binary)
    args.module = trusted_path(args.module)
    args.library_dir = trusted_path(args.library_dir, directory=True)
    if args.nginx_binary.name not in ("nginx", "nginx-binary") or not os.access(args.nginx_binary, os.X_OK):
        raise ValueError("executable NGINX artifact required")
    # The command and every argument are validated paths or fixed parser flags;
    # neither shell syntax nor NGINX configuration delimiters are accepted.
    executable = re.fullmatch(ARTIFACT_PATH_PATTERN, str(args.nginx_binary)).group(0)
    args.output.mkdir(mode=0o700)
    cases = [
        ("historical-minimal", "modsecurity_phase4_mode minimal;", 1, "expected off|safe|strict"),
        ("historical-host-mime-gate", 'modsecurity_phase4_content_types_file "' + str(args.output / SCOPE_FILENAME) + '";', 1,
         'unknown directive "modsecurity_phase4_content_types_file"'),
        ("supported-safe", "modsecurity_phase4_mode safe;", 0, "test is successful"),
        ("supported-strict", "modsecurity_phase4_mode strict;", 0, "test is successful"),
    ]
    (args.output / SCOPE_FILENAME).write_text("application/json\n")
    environment = {"PATH": "/usr/bin:/bin", "LD_LIBRARY_PATH": str(args.library_dir)}
    rows = []
    for label, directive, expected, diagnostic in cases:
        configuration = args.output / (label + ".conf")
        configuration.write_text(f'load_module "{args.module}";\nuser nobody nogroup;\n'
            + f'pid "{args.output}/{label}.pid";\nerror_log stderr;\nevents {{}}\nhttp {{ {directive} }}\n')
        configuration_argument = re.fullmatch(ARTIFACT_PATH_PATTERN, str(configuration)).group(0)
        prefix_argument = re.fullmatch(ARTIFACT_PATH_PATTERN, str(args.output) + "/").group(0)
        argv = [executable, "-e", "stderr", "-t", "-c", configuration_argument, "-p", prefix_argument]
        child = subprocess.run(argv, env=environment, capture_output=True, timeout=15, shell=False)
        (args.output / (label + ".stdout")).write_bytes(child.stdout)
        (args.output / (label + ".stderr")).write_bytes(child.stderr)
        rows.append({"label": label, "argv": argv, "actual_exit": child.returncode,
            "signal": -child.returncode if child.returncode < 0 else None,
            "expected_exit": expected, "diagnostic": diagnostic,
            "matched": child.returncode == expected and diagnostic.encode() in child.stderr,
            "configuration_sha256": sha(configuration), "stderr_sha256": sha(args.output / (label + ".stderr")),
            "http_requests_sent": 0, "host_started": False})
    receipt = {"scope": "Native parser only; no HTTP or lifecycle qualification", "rows": rows,
        "module_sha256": sha(args.module), "binary_sha256": sha(args.nginx_binary),
        "rules_scope_file_sha256": sha(args.output / SCOPE_FILENAME), "all_expected": all(row["matched"] for row in rows)}
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))
    return 0 if receipt["all_expected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
