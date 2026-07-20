"""Hermetic fake-Git program builders for provenance-boundary tests."""

from __future__ import annotations


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
