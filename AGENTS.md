# Framework Local Codex Instructions

<!-- codex-control-plane-routing:framework -->

## Scope

These instructions govern the Framework repository at:

`/root/git/ModSecurity-conector/modules/ModSecurity-test-Framework`

The Framework is a separate Git, test, evidence, review, and delivery unit. It owns reusable YAML cases, runners, normalizers, catalog checks, and report generators. It does not own Parent connector implementations or connector runtime promotion.

## Mandatory startup order

For every Framework task:

1. read `/root/.agents/skills/goal-driven-execution/SKILL.md`;
2. read `/root/.codex/RTK.md` before shell/project commands;
3. when this checkout is nested below the Parent, read Parent `AGENTS.md`, Parent `.codex/context/index.md`, and Parent `.codex/inheritance-manifest.toml`;
4. read this `AGENTS.md`;
5. read `.codex/inheritance-manifest.toml` and `.codex/context/index.md`;
6. load only the inherited Parent owners and Framework-local delta policies required by the task.

Do not copy Parent policy bodies into Framework context files. Parent rules are inherited by digest-pinned policy IDs; Framework-local policies only add stricter repository-specific rules.

## Core boundaries

- Parent: `/root/git/ModSecurity-conector`
- Framework: this repository
- MRTS: `tools/MRTS`

A Framework task never authorizes Parent writes, Parent gitlink updates, MRTS writes, another repository's commit/PR, or another repository's merge.

MRTS is read-only by default during Framework work. A separate current user request is required to start an independent MRTS task.

## Task contract

Use the global goal-driven execution skill for the execution contract, plan, milestones, validation, and completion reconciliation.

For Framework work also record:

- Framework-owned files;
- Framework validation commands/results;
- Framework documentation impact;
- Framework delivery state;
- Parent impact;
- Parent gitlink disposition: `unchanged | update_required | updated`;
- MRTS impact: `default_read_only | separately_user_selected_mrts_task`.

## Command execution

RTK is mandatory for local shell/project commands. Parent `PARENT-COMMAND-EXECUTION` is the canonical execution policy.

The Framework root `Makefile` and current versioned Framework documentation are the command sources of truth. Do not maintain a second static command catalog in `.codex`.

## Runtime and storage

Use the roots supplied by the active Framework `.codex/config.toml`. Build output, source materialization, logs, caches, temporary files, analysis artifacts, and evidence belong outside the Git worktree under `/var/tmp/codex/ModSecurity-test-Framework` unless an active higher-priority configuration says otherwise.

Do not use Parent or MRTS checkouts as overflow storage.

## Python

Framework Python dependencies belong to the Framework repository. Use the Framework-owned interpreter/environment selected by `.codex/config.toml` and `python-policy.md`.

Do not silently use the Parent `.venv`. A shared Parent/Framework Python environment requires an explicit compatibility/lock contract.

## Testing and evidence

Framework results preserve the distinction between static/catalog checks, starter checks, host runtime evidence, generated reports, and connector promotion.

A Framework PASS does not by itself prove host runtime support. `BLOCKED` and `NOT_EXECUTABLE` are not PASS. Connector capabilities and promotion remain connector-owned.

## Git and delivery

Framework delivery is independent from Parent and MRTS delivery. Preserve unrelated changes and use task-owned branches/worktrees for non-trivial versioned work unless the current user explicitly selects the existing checkout.

The highest automatic Framework delivery state is `verified_pr`. Direct `master` push, force-push, administrative bypass, weakened checks, and automatic merge are forbidden. Integration into Framework `master` requires current explicit Framework-scoped authorization and exact-head verification.

A successful Framework merge never automatically updates the Parent Framework gitlink.

## Documentation and traceability

Reader-facing Framework documentation is maintained in English/German pairs where the repository contract requires them. Non-trivial Framework changes require the Framework-owned paired Change Record under `reports/audits/change-records/` when the repository contract applies.

Generated reports are changed only through their generator.

## Context routing

| Task | Load Framework delta |
| --- | --- |
| Ownership / Parent separation | `.codex/context/repository-boundaries.md` |
| Test selection / evidence interpretation | `.codex/context/testing-and-evidence.md` |
| Framework security work | `.codex/context/security-policy.md` |
| Git / PR / Framework delivery | `.codex/context/delivery-policy.md` |
| MRTS inspection or interaction | `.codex/context/mrts-boundary-policy.md` |
| Framework Python | `.codex/context/python-policy.md` |
| Documentation / Change Records | `.codex/context/documentation-and-traceability.md` |
| Cleanup / restoration | `.codex/context/cleanup-and-restoration.md` |
| Final completion decision | `.codex/context/definition-of-done.md` |

Parent-wide topics such as RTK, SonarQube authentication, generic Git safety, generic PR remediation, resources, subagents, finding lifecycle, and task workflow remain owned by their inherited Parent policy IDs.
