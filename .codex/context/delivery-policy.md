# Framework Delivery Delta

## Independent delivery

Framework branches, commits, pushes, PRs, CI, reviews, SonarQube results, and merge authorization belong to the Framework repository.

Do not combine Parent or MRTS files in a Framework commit.

## Default endpoint

The highest automatic delivery state is `verified_pr`.

Direct default-branch push, force-push, history rewrite, administrative bypass, weakened checks, and automatic merge are forbidden.

Framework `master` integration requires current explicit Framework-scoped authorization and exact PR head verification under inherited `PARENT-MASTER-INTEGRATION`.

## Parent gitlink

A Framework commit/PR/merge never automatically changes the Parent Framework gitlink. Report the exact Framework SHA; Parent pointer work is a separate Parent task/authorization.

## Remediation

Task-owned Framework CI/review/Sonar remediation may proceed only under inherited delivery/remediation policies and remains Framework-scoped.
