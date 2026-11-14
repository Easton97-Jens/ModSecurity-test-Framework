# Change record

**Language:** English | [Deutsch](20261114-02-nginx-review-runner-boundaries.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261114-02-nginx-review-runner-boundaries |
| UTC date | 2026-11-14 |
| Framework base revision | Candidate HEAD `6aaf2e153146fd2aa925666b42ed74985ca8543c`, incoming `3ff8b75c9f4d2cb3614a4dcb7afd2e5360e074d8` |
| Issue or pull request | Framework [#169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169); incoming runner from [#171](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/171) |

## Motivation and problem statement

The review runner could admit output inside a CLI-selected checkout different from its environment roots, including linked-worktree Git metadata. SIGTERM or an already-reaped master could also leave its server group running.

## Affected components and security boundaries

Framework files `connector_suite/modsecurity_connector_tests/run_nginx_fzipi_review.py` and `connector_suite/modsecurity_connector_tests/test_nginx_fzipi_runner.py`: output admission and the runner's owned process group. Parent and MRTS source remain outside this change.

## Acceptance criteria

Reject output overlapping the actual CLI checkout, Git directory or common Git directory before creation; retain external siblings. Cancellation must reap the owned group, close its listener, restore the handler and report exit 143. Preserve the original 19 methods, artifact guards and ordinary cleanup receipt.

## Alternatives considered

Environment-only roots and master-only waiting miss the reproduced paths. Blocking SIGTERM across `Popen` risks inheriting the mask. An idempotent handler alone also failed on the first signal during normal context exit.

## Implementation decision

Admission includes canonical CLI/Git roots before runtime creation. Scoped pending cancellation covers spawn handoff; cleanup state and nested `finally` protect shutdown and handler restoration. Pending cancellation after normal exit still raises 143. Graceful master SIGQUIT precedes bounded group TERM/KILL, including after master reaping. The child signal mask and zombie visibility remain intact.

## Changed files and tests

The two Python files and this EN/DE pair change. Eight methods are added: one real ordinary/linked-Git regression and seven real process controls. All original 19 methods remain unchanged; total 27. Controls cover live cancellation, spawn return, repeated cleanup signals, already-reaped master, TERM/KILL escalation and both repeated/first SIGTERM immediately before SIG_IGN. Private process-local subreapers also clean up failing negative controls.

## Commands and results

Commands used the selected Framework-owned Python 3.15, explicit source roots and external temporary/cache roots. Exact arguments and hashes remain in private receipts.

| Command or procedure | Exit code | Result | Run ID |
| --- | --- | --- | --- |
| Original-runner real Git control | 1 | Five expected missing rejections; external sibling controls admitted | `runner171-fix-5408725399ea4aafa2a28d4d25a23eee` |
| Original-runner five real process controls | 1 | Five expected failures; guardian removed every group | `runner171-old-process-shadow-d40e78644403447fa2431623d1a55958` |
| Repeated SIGTERM before SIG_IGN against first fix | 1 | Expected skipped cleanup and open listener | `runner171-before-ignore-shadow-17cef617e551443aaf98fba9a3508126` |
| First SIGTERM during normal exit against idempotent-only candidate | 1 | Expected skipped cleanup; guardian removed group | `runner171-normal-exit-shadow-8039fa69c9734abd93cec6f77ff25dad` |
| `rtk bypass "$PYTHON" -B -P -m unittest -v modsecurity_connector_tests.test_nginx_fzipi_runner` | 0 | 27 passed, no failures/errors/skips; 39.918 seconds | `runner171-final27-controls-72c5c570c1ab4840854d5299b83199ed` |
| Python `py_compile` for both changed files | 0 | Source unchanged; external bytecode cache | `runner171-python-qa-3fb91e9d36b24943904148b6d9c49a3b` |
| Framework Python `-m ruff --version` and `-m pyright --version` | 1 each | Both modules unavailable; QA checks NOT_RUN | `runner171-python-qa-3fb91e9d36b24943904148b6d9c49a3b` |

## Security impact

Original bypass and lifecycle paths were reproduced and then passed with the fix. Passing process controls require no guardian intervention, absent groups, a closed listener, handler restoration and the expected worker exit. Artifact/provenance, ownership, symlink, manifest, grammar, host-admission and Quality Gate controls remain unchanged. Explicit Secrets qualification is separate from incomplete automatic edit-hook events.

## Documentation and runtime evidence

This record has an equivalent German companion. Real processes and loopback listeners were disposable regression fixtures. Native NGINX/ModSecurity host scenarios, connector matrix and comprehensive acceptance remain NOT_RUN.

## Checks not run

Local Ruff/Pyright checks lack existing tools in the selected Framework environment and registered executable paths. No installation or analysis/gate change was made. Fresh hosted checks at the eventual Framework commit remain required.

## Limitations and residual risk

Process controls require Linux fork, process-local subreapers and loopback sockets. They qualify runner boundaries; real connector artifacts/runtime require their own admission and evidence. Local Python QA remains partial.

## Final diff and review status

The bound final sources passed all 27 methods and Python syntax compilation; independent static review cleared the fix. This pair is prepared for Framework delivery. Native generated-view refresh, documentation checks, publication and current-head hosted evidence follow under the delivery owner.
