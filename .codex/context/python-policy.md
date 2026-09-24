# Framework Python Policy Delta

Framework Python dependencies and test-tool compatibility belong to the Framework repository.

Use the Framework-owned environment selected by `.codex/config.toml`:

- `VIRTUAL_ENV=/var/tmp/codex/ModSecurity-test-Framework/venv`
- `PYTHON=/var/tmp/codex/ModSecurity-test-Framework/venv/bin/python`

Create/recreate that environment with a repository-compatible interpreter when required. Do not silently substitute the Parent `.venv`, system/user-site packages, or an MRTS environment.

Use explicit `PYTHON`/`python -m ...` invocation through the mandatory RTK execution path. Keep bytecode/cache under the configured external cache root.

A shared Parent/Framework environment is permitted only when the current task has a documented compatibility and lock contract proving the same dependency set is valid for both repositories.

Repository dependency changes require Framework-owned lock/requirements/test/documentation handling and normal Framework delivery.
