# Framework Cleanup and Restoration Delta

Clean only task-owned Framework resources, external worktrees, temporary data, processes, ports, and runtime artifacts.

Never use broad `git clean`, `git reset --hard`, or unbounded recursive deletion to restore Framework state.

For standalone Framework work, restore only when safe and authorized. Preserve unrelated user state and open task branches/PRs that still require remediation.

When a Framework task is coordinated from Parent and no Parent gitlink update is authorized, inherited `PARENT-FRAMEWORK-ORCHESTRATION` owns the no-pointer restoration rule: return the Framework worktree to the exact Parent-recorded commit only when this can be done without losing task/user state.

MRTS cleanup is never part of Framework cleanup unless a separate MRTS task explicitly owns those resources.
