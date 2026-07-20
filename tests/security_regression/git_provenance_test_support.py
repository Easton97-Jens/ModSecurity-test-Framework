"""Hermetic fake-Git program builders for provenance-boundary tests."""

from __future__ import annotations


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


def fake_git_script(approved_repo: str, approved_commit: str) -> str:
    """Build the narrowly scoped Git stand-in used by immutable-source tests."""

    lines = (
        "#!/usr/bin/env python3",
        "import os",
        "from pathlib import Path",
        "import sys",
        "",
        f"approved_repo = {approved_repo!r}",
        f"approved_commit = {approved_commit!r}",
        'log = Path(os.environ["FAKE_GIT_LOG"])',
        'with log.open("a", encoding="utf-8") as handle:',
        '    handle.write(" ".join(sys.argv[1:]) + "\\n")',
        "",
        "for untrusted_environment_name in (",
        '    "GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_PARAMETERS", "GIT_SSL_NO_VERIFY", "GIT_ASKPASS",',
        "):",
        "    if untrusted_environment_name in os.environ:",
        "        sys.exit(91)",
        "",
        "arguments = sys.argv[1:]",
        "repository = None",
        "offset = 0",
        "while offset + 1 < len(arguments) and arguments[offset] in {'-c', '-C'}:",
        "    if arguments[offset] == '-C':",
        "        repository = arguments[offset + 1]",
        "    offset += 2",
        "command = arguments[offset] if offset < len(arguments) else ''",
        "arguments = arguments[offset + 1:]",
        "if command == 'init':",
        "    Path(arguments[-1], '.git').mkdir(parents=True, exist_ok=True)",
        "elif command == 'config':",
        "    print(os.environ.get('FAKE_GIT_ORIGIN', approved_repo))",
        "elif command == 'fetch':",
        "    sys.exit(int(os.environ.get('FAKE_GIT_FETCH_RC', '0')))",
        "elif command == 'checkout' and os.environ.get('FAKE_GIT_CREATE_GITMODULES') == '1' and repository:",
        "    Path(repository, '.gitmodules').touch()",
        "elif command == 'rev-parse':",
        "    if any(argument.startswith('FETCH_HEAD') for argument in arguments):",
        "        print(os.environ.get('FAKE_GIT_FETCH_HEAD_COMMIT', approved_commit))",
        "    elif any(argument.startswith('HEAD') for argument in arguments):",
        "        print(os.environ.get('FAKE_GIT_HEAD_COMMIT', approved_commit))",
        "    else:",
        "        print(os.environ.get('FAKE_GIT_RESOLVED_COMMIT', approved_commit))",
        "elif command == 'ls-files' and os.environ.get('FAKE_GIT_GITLINK') == '1':",
        "    print('160000 ' + ('f' * 40) + ' 0\\tthird-party')",
    )
    return "\n".join(lines) + "\n"
