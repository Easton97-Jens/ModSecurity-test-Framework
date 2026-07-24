"""Hermetic fake-Git program builders for provenance-boundary tests."""

from __future__ import annotations

import os
from pathlib import Path


APPROVED_MODSECURITY_V3_ROOT_LINKS = (
    ("bindings/python", "bc625d5bb0bac6a64bcce8dc9902208612399348"),
    ("others/libinjection", "211782219663f889f471650150df12b623c5766e"),
    ("others/mbedtls", "0fe989b6b514192783c469039edd325fd0989806"),
    (
        "test/test-cases/secrules-language-tests",
        "a3d4405e5a2c90488c387e589c5534974575e35b",
    ),
)

# path, origin, commit, Gitdir relative to the root .git/modules directory,
# and the direct Gitlinks tracked by that child.
APPROVED_MODSECURITY_V3_TOPOLOGY = (
    (
        "bindings/python",
        "https://github.com/owasp-modsecurity/ModSecurity-Python-bindings.git",
        "bc625d5bb0bac6a64bcce8dc9902208612399348",
        "bindings/python",
        (),
    ),
    (
        "others/libinjection",
        "https://github.com/libinjection/libinjection.git",
        "211782219663f889f471650150df12b623c5766e",
        "others/libinjection",
        (),
    ),
    (
        "others/mbedtls",
        "https://github.com/Mbed-TLS/mbedtls.git",
        "0fe989b6b514192783c469039edd325fd0989806",
        "others/mbedtls",
        (
            ("framework", "dff9da04438d712f7647fd995bc90fadd0c0e2ce"),
            ("tf-psa-crypto", "29160dd877d29658279fd683b2ae57b320ddcf09"),
        ),
    ),
    (
        "others/mbedtls/framework",
        "https://github.com/Mbed-TLS/mbedtls-framework",
        "dff9da04438d712f7647fd995bc90fadd0c0e2ce",
        "others/mbedtls/modules/framework",
        (),
    ),
    (
        "others/mbedtls/tf-psa-crypto",
        "https://github.com/Mbed-TLS/TF-PSA-Crypto.git",
        "29160dd877d29658279fd683b2ae57b320ddcf09",
        "others/mbedtls/modules/tf-psa-crypto",
        (
            (
                "drivers/pqcp/mldsa-native",
                "5772b4f4a0105694b1203abb582273f78fa951b7",
            ),
            ("framework", "dff9da04438d712f7647fd995bc90fadd0c0e2ce"),
        ),
    ),
    (
        "others/mbedtls/tf-psa-crypto/drivers/pqcp/mldsa-native",
        "https://github.com/Mbed-TLS/mldsa-native",
        "5772b4f4a0105694b1203abb582273f78fa951b7",
        "others/mbedtls/modules/tf-psa-crypto/modules/mldsa-native",
        (),
    ),
    (
        "others/mbedtls/tf-psa-crypto/framework",
        "https://github.com/Mbed-TLS/mbedtls-framework",
        "dff9da04438d712f7647fd995bc90fadd0c0e2ce",
        "others/mbedtls/modules/tf-psa-crypto/modules/framework",
        (),
    ),
    (
        "test/test-cases/secrules-language-tests",
        "https://github.com/owasp-modsecurity/secrules-language-tests",
        "a3d4405e5a2c90488c387e589c5534974575e35b",
        "test/test-cases/secrules-language-tests",
        (),
    ),
)


def assert_immutable_commit_fetch_control(
    test_case,
    result,
    commands: list[str],
    git_verbs,
    approved_repo: str,
    approved_commit: str,
) -> str:
    """Assert the shared positive control for a fixed-origin detached Git fetch."""
    command_text = "\n".join(commands)
    test_case.assertEqual(0, result.returncode, result.stdout + result.stderr)
    test_case.assertIn("init ", command_text)
    test_case.assertIn(f"remote add origin {approved_repo}", command_text)
    test_case.assertIn("config --get remote.origin.url", command_text)
    test_case.assertIn(f"fetch --depth 1 --no-tags origin {approved_commit}", command_text)
    test_case.assertIn("rev-parse --verify FETCH_HEAD^{commit}", command_text)
    test_case.assertIn(f"rev-parse --verify {approved_commit}^{{commit}}", command_text)
    test_case.assertIn(f"checkout --detach {approved_commit}", command_text)
    test_case.assertIn("rev-parse --verify HEAD^{commit}", command_text)
    test_case.assertNotIn("clone", git_verbs(commands))
    test_case.assertNotIn("submodule", git_verbs(commands))
    test_case.assertIn("-c core.hooksPath=/dev/null", command_text)
    test_case.assertIn("-c protocol.file.allow=never", command_text)
    test_case.assertIn("-c fetch.recurseSubmodules=false", command_text)
    test_case.assertIn("-c submodule.recurse=false", command_text)
    test_case.assertIn("-c http.sslVerify=true", command_text)
    return command_text


def create_approved_modsecurity_v3_topology(
    source_dir: Path,
    *,
    missing_path: str | None = None,
    symlink_path: str | None = None,
) -> None:
    """Create only the private checkout shape consumed by the fake Git helper."""

    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / ".git").mkdir(exist_ok=True)
    (source_dir / ".gitmodules").write_text("[submodule]\n", encoding="utf-8")
    for path, _, _, gitdir_relative, _ in APPROVED_MODSECURITY_V3_TOPOLOGY:
        if path == missing_path:
            continue
        checkout = source_dir / path
        checkout.parent.mkdir(parents=True, exist_ok=True)
        if path == symlink_path:
            target = source_dir.parent / "symlink-target"
            target.mkdir(exist_ok=True)
            os.symlink(target, checkout, target_is_directory=True)
            continue
        checkout.mkdir(exist_ok=True)
        gitdir = source_dir / ".git/modules" / gitdir_relative
        gitdir.mkdir(parents=True, exist_ok=True)
        (checkout / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")


def fake_git_script(approved_repo: str, approved_commit: str) -> str:
    """Build a fake Git that models the exact approved recursive V3 graph."""

    script = """#!/usr/bin/env python3
import os
from pathlib import Path
import sys

approved_repo = __APPROVED_REPO__
approved_commit = __APPROVED_COMMIT__
root_links = __ROOT_LINKS__
topology = __TOPOLOGY__
topology_by_path = {entry[0]: entry for entry in topology}

log = Path(os.environ["FAKE_GIT_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(" ".join(sys.argv[1:]) + "\\n")

root = Path(os.environ["FAKE_GIT_ROOT"]).resolve()
for untrusted_environment_name in (
    "GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_PARAMETERS", "GIT_SSL_NO_VERIFY", "GIT_ASKPASS",
):
    if untrusted_environment_name in os.environ:
        if untrusted_environment_name == "GIT_DIR" and Path(os.environ["GIT_DIR"]).resolve() == root / ".git":
            continue
        if untrusted_environment_name == "GIT_WORK_TREE" and Path(os.environ["GIT_WORK_TREE"]).resolve() == root:
            continue
        sys.exit(91)

def relative_path(repository):
    if repository is None:
        return ""
    try:
        relative = Path(repository).resolve().relative_to(root)
        return "" if relative == Path(".") else str(relative)
    except ValueError:
        return "__outside__"

def metadata(relative):
    if not relative:
        return approved_repo, approved_commit, "", root_links
    entry = topology_by_path.get(relative)
    if entry is None:
        return "", "", "", ()
    return entry[1], entry[2], entry[3], entry[4]

def make_topology():
    root.mkdir(parents=True, exist_ok=True)
    (root / ".git").mkdir(exist_ok=True)
    (root / ".gitmodules").write_text("[submodule]\\n", encoding="utf-8")
    missing_path = os.environ.get("FAKE_GIT_TOPOLOGY_MISSING")
    symlink_path = os.environ.get("FAKE_GIT_TOPOLOGY_SYMLINK")
    for path, _, _, gitdir_relative, _ in topology:
        if path == missing_path:
            continue
        checkout = root / path
        checkout.parent.mkdir(parents=True, exist_ok=True)
        if path == symlink_path:
            target = root.parent / "fake-git-symlink-target"
            target.mkdir(exist_ok=True)
            os.symlink(target, checkout, target_is_directory=True)
            continue
        checkout.mkdir(exist_ok=True)
        gitdir = root / ".git/modules" / gitdir_relative
        gitdir.mkdir(parents=True, exist_ok=True)
        (checkout / ".git").write_text(f"gitdir: {gitdir}\\n", encoding="utf-8")

arguments = sys.argv[1:]
repository = os.environ.get("GIT_WORK_TREE") or os.getcwd()
offset = 0
while offset < len(arguments):
    if arguments[offset] == "--no-optional-locks":
        offset += 1
    elif arguments[offset].startswith("--git-dir="):
        offset += 1
    elif arguments[offset].startswith("--work-tree="):
        repository = arguments[offset].split("=", 1)[1]
        offset += 1
    elif arguments[offset] in {"--git-dir", "--work-tree"} and offset + 1 < len(arguments):
        if arguments[offset] == "--work-tree":
            repository = arguments[offset + 1]
        offset += 2
    elif arguments[offset] in {"-c", "-C"} and offset + 1 < len(arguments):
        if arguments[offset] == "-C":
            repository = arguments[offset + 1]
        offset += 2
    else:
        break
command = arguments[offset] if offset < len(arguments) else ""
arguments = arguments[offset + 1:]
relative = relative_path(repository)
origin, commit, gitdir_relative, direct_links = metadata(relative)

if command == "init":
    root.mkdir(parents=True, exist_ok=True)
    (root / ".git").mkdir(exist_ok=True)
    Path(arguments[-1], ".git").mkdir(parents=True, exist_ok=True)
elif command == "config":
    if "--name-only" in arguments:
        if os.environ.get("FAKE_GIT_SUBMODULE_UPDATE_CONFIG") == "1":
            print("submodule.attacker.update")
    elif "--get-all" in arguments:
        sys.exit(1)
    elif "--unset-all" in arguments:
        sys.exit(0)
    elif relative:
        if os.environ.get("FAKE_GIT_CHILD_ORIGIN_MISMATCH") == "1":
            print("https://github.com/attacker/ModSecurity.git")
        else:
            print(origin)
    else:
        print(os.environ.get("FAKE_GIT_ORIGIN", approved_repo))
elif command == "remote":
    if not arguments or arguments[0] != "add":
        print("origin")
        if os.environ.get("FAKE_GIT_EXTRA_REMOTE") == "1":
            print("attacker")
elif command == "fetch":
    sys.exit(int(os.environ.get("FAKE_GIT_FETCH_RC", "0")))
elif command == "checkout":
    if repository and not os.environ.get("FAKE_GIT_ROOT_GITMODULES_MISSING"):
        Path(repository, ".gitmodules").write_text("[submodule]\\n", encoding="utf-8")
elif command == "submodule":
    rc = int(os.environ.get("FAKE_GIT_SUBMODULE_RC", "0"))
    if rc:
        sys.exit(rc)
    make_topology()
elif command == "symbolic-ref":
    if os.environ.get("FAKE_GIT_ATTACHED_HEAD") == "1":
        print("refs/heads/main")
        sys.exit(0)
    sys.exit(1)
elif command == "rev-parse":
    if "--show-toplevel" in arguments:
        if os.environ.get("FAKE_GIT_WORKTREE_REDIRECT") == "1":
            redirect = root.parent / "redirected-worktree"
            redirect.mkdir(exist_ok=True)
            print(redirect)
        else:
            print(repository)
    elif "--absolute-git-dir" in arguments:
        if os.environ.get("FAKE_GIT_GITDIR_ESCAPE") == "1" and relative:
            escaped = root.parent / "escaped-gitdir"
            escaped.mkdir(exist_ok=True)
            print(escaped)
        else:
            if relative:
                gitdir = root / ".git/modules" / gitdir_relative
            else:
                gitdir = root / ".git"
            gitdir.mkdir(parents=True, exist_ok=True)
            print(gitdir)
    elif any(argument.startswith("FETCH_HEAD") for argument in arguments):
        print(os.environ.get("FAKE_GIT_FETCH_HEAD_COMMIT", approved_commit))
    elif any(argument.startswith("HEAD") for argument in arguments):
        if relative and os.environ.get("FAKE_GIT_CHILD_COMMIT_MISMATCH") == "1":
            print("a" * 40)
        elif relative:
            print(commit)
        else:
            print(os.environ.get("FAKE_GIT_HEAD_COMMIT", approved_commit))
    else:
        print(os.environ.get("FAKE_GIT_RESOLVED_COMMIT", approved_commit))
elif command == "fsck":
    sys.exit(int(os.environ.get("FAKE_GIT_FSCK_RC", "0")))
elif command == "status":
    if os.environ.get("FAKE_GIT_DIRTY") == "1":
        print(" M tracked-file")
elif command == "ls-files":
    if "--stage" in arguments:
        links = list(direct_links)
        if not relative and os.environ.get("FAKE_GIT_TOPOLOGY_EXTRA") == "1":
            links.append(("unexpected-child", "f" * 40))
        for path, sha in links:
            print(f"160000 {sha} 0\\t{path}")
    elif "-v" in arguments:
        print("h hidden-file" if os.environ.get("FAKE_GIT_INDEX_FLAG") == "1" else "H tracked-file")
"""
    return (
        script.replace("__APPROVED_REPO__", repr(approved_repo))
        .replace("__APPROVED_COMMIT__", repr(approved_commit))
        .replace("__ROOT_LINKS__", repr(APPROVED_MODSECURITY_V3_ROOT_LINKS))
        .replace("__TOPOLOGY__", repr(APPROVED_MODSECURITY_V3_TOPOLOGY))
    )
