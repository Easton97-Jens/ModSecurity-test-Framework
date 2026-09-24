# MRTS Boundary for Framework Work

`tools/MRTS` is a separate nested Git repository and is read-only by default during Framework work.

Framework work may inspect MRTS when required by a test/evidence contract, but must not:

- edit, generate, install, or create environments inside MRTS;
- switch/reset/clean/stash MRTS;
- create MRTS branches, commits, pushes, or PRs;
- update the Framework MRTS gitlink;
- treat an MRTS result as Framework authority.

If Framework validation requires writable MRTS-like material, use a task-owned external copy/output root when technically valid.

A current top-level user may separately select an MRTS task. That task follows MRTS-local instructions and never grants Framework gitlink or delivery authority.
