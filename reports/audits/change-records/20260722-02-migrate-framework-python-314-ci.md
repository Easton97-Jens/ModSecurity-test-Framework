# Change record — 20260722-02-migrate-framework-python-314-ci

**Language:** English | [Deutsch](20260722-02-migrate-framework-python-314-ci.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260722-02-migrate-framework-python-314-ci` |
| UTC date | `2026-07-22` |
| Framework branch predecessor revision | `1fd3b362e0fed9766c6920e3c7bd1939535850f2` |
| Hosted PR base revision | `f73f8842f45318e2df8aff1d31855eeb7c20a22f` |
| Issue or pull request | Framework PR #42; the initial CPython-3.14.6 migration was submitted as `e0564d219980d62bc37162ac6c11641f289f1b71`. Hosted CPython 3.14.6 availability and Sonar passed there, while OSV exposed a trusted-base CP313/PR-head CP314 lock mismatch and Ruff reported formatting drift. The security-preserving source follow-up at `2930e04e1558b5b10bdeb87a76abb077a2085566` corrected those controls and the focused Pyright test-fixture typing issue. Its hosted `python-ci-security-quality` run `29962792445` / job `89067507532`, repaired OSV control, all non-skipped PR checks, and PR SonarQube Cloud Quality Gate passed. Resulting-master evidence is unobserved; every later PR head requires fresh exact-head evidence. |

## Motivation and problem statement

The Framework's CI Python baseline must move from the prior CPython 3.13 contract to reviewed CPython `3.14.6` without weakening its provenance, version-selection, or untrusted-pull-request controls. The canonical selector, candidate maintainer, CI workflow, strict hash-locked dependency artifact, and static-tool baselines must change together to avoid a contradictory CI contract.

The OSV pull-request design executes the trusted base revision. It selects its
interpreter only from that base's bounded blob selector. The exact historical
base `f73f8842f45318e2df8aff1d31855eeb7c20a22f` predates that selector and
alone receives fixed `3.13.14` to match its CP313-only trusted lock. This
migration updates every other normal path to stable CPython 3.14 while
preserving its no-PR-head-selector, no-PR-head-checkout, and
no-PR-head-execution boundary.

## Affected components and security boundaries

The Framework-only boundary is CI interpreter/dependency provenance and workflow trust. The intended migration contract covers:

- `.python-version` as the canonical regular, non-symlink selector with strict newline-terminated stable `3.14.<numeric patch>` grammar;
- `.github/workflows/check-python-version.yml`, its fixed `${{ runner.temp }}/framework-python-3.14-candidate` path, and review branch `automation/update-framework-python-314`;
- `ci/checks/security/check-python-version.py`, `ci/checks/security/check-ci-security-contract.py`, and `ci/tools/update-python-version.py` as the enforcing/checking/updating boundary;
- `requirements-ci.lock` with the reviewed CP314 PyYAML artifact and hash;
- `pyproject.toml` Ruff `py314`, `pyrightconfig.json` Python `3.14`, and the paired CI-security documentation and Change Record.

The updater trusts only its documented public Python.org JSON authority and does not use a GitHub token, follow redirects, scrape HTML, or write a repository path other than `.python-version`. The OSV PR job retains its trusted-base checkout, bounded head-manifest reads, base-interpreter/base-lock ABI pairing, and no-PR-head-execution invariant. No Parent source, Parent gitlink, connector runtime, or `tools/MRTS` content is in scope.

## Acceptance criteria

1. `.python-version` is a regular non-symlink UTF-8 file containing exactly the newline-terminated stable value `3.14.6`, and the contract rejects floating selectors, wildcards, prereleases, and malformed variants.
2. Active `actions/setup-python` uses select the canonical file with `python-version-file: .python-version` and `check-latest: false`, except only the independently verified candidate file and the OSV private trusted-base bootstrap file.
3. `check-python-version.yml` is scheduled/manual only, separates read-only resolution from candidate validation, materializes only `${{ runner.temp }}/framework-python-3.14-candidate`, and permits its publisher only for a revalidated candidate gated by `github.ref == 'refs/heads/master'`.
4. The publisher can create or update only a Draft PR on `automation/update-framework-python-314` whose allowed change path is `.python-version`; it neither auto-merges nor accepts a floating version.
5. The native updater accepts only published stable CPython 3.14 patch metadata from Python.org and preserves its fail-closed, no-redirect, single-file-write behavior.
6. `requirements-ci.lock` names `PyYAML-6.0.3-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` and official SHA-256 `c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5`, while retaining `--require-hashes` and `--only-binary=:all:`.
7. Ruff and Pyright use the explicit `py314` and `3.14` baselines.
8. The OSV PR path executes only the trusted base revision and selects a strict stable CPython-3.14 value from its bounded base blob. Only exact pre-selector base `f73f8842f45318e2df8aff1d31855eeb7c20a22f` may use `3.13.14`; every other CP313 selector or missing base file fails closed. It must not read a PR-head Python selector, check out, or execute PR-head source or workflow content.
9. English/German guide, README index, and Change Record pair remain equivalent and contain no invented local, hosted, runtime, delivery, or security-finding result.

## Alternatives considered

- Retaining CPython 3.13 would leave the requested 3.14.6 migration incomplete.
- A mutable, wildcard, or `check-latest` selector would weaken the reproducible reviewed-version contract.
- Removing `--require-hashes`, allowing a source build, or retaining a CP313 wheel would weaken or break the CP314 dependency boundary.
- Checking out or executing PR-head content in the OSV job would broaden the untrusted workflow/source execution boundary and is rejected.
- A generic publisher branch or broader file allowlist would make maintenance less reviewable; the fixed branch and `.python-version` allowlist are retained.

## Implementation decision

The selected baseline is exact CPython `3.14.6`. `.python-version` remains the single source of interpreter selection, with strict stable `3.14.<numeric patch>` grammar and a terminal newline. The candidate job is the only maintenance exception and may pass an independently validated candidate through `${{ runner.temp }}/framework-python-3.14-candidate`. OSV `pull-request-head` may use only its fixed private trusted-base bootstrap file: it copies a bounded base blob and accepts strict 3.14, except for exact pre-selector base `f73f8842f45318e2df8aff1d31855eeb7c20a22f`, which alone selects `3.13.14` to match its CP313 hash lock. The exception authorizes neither a broad file path nor a floating version, PR-head Python selector, or PR-head source execution.

`ci/tools/update-python-version.py` remains the native Python.org JSON updater. `check-python-version.yml` resolves, validates, then conditionally publishes a Draft maintenance PR. Its publisher independently re-resolves and revalidates the candidate, is gated by `github.ref == 'refs/heads/master'`, uses `automation/update-framework-python-314`, and permits `.python-version` as its sole change path. `pyproject.toml` and `pyrightconfig.json` move together to `py314` and `3.14` so static analysis uses the reviewed baseline.

The CP314 dependency tuple is `PyYAML-6.0.3-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` with official SHA-256 `c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5`. The lock continues to require a binary artifact, exact hash, and `pip check`; it does not add automatic dependency remediation.

## Changed files and tests

The CPython-3.14.6 migration changes the canonical selector, static-analysis
baseline, CP314 lock tuple, Python-maintenance and OSV workflows, their three
enforcing/checking/updating Python paths, and their focused regression coverage:

- `.python-version`, `pyproject.toml`, `pyrightconfig.json`, and `requirements-ci.lock`;
- `.github/workflows/check-python-version.yml` and `.github/workflows/ci-security-osv.yml`;
- `ci/tools/update-python-version.py`,
  `ci/checks/security/check-python-version.py`, and
  `ci/checks/security/check-ci-security-contract.py`;
- `tests/ci_security/test_update_python_version.py`,
  `tests/ci_security/test_python_version_contract.py`,
  `tests/ci_security/test_ci_security_contract.py`, and
  `tests/ci_security/test_framework_ci_security_contract.py`; and
- the paired CI-security guide, paired README index, and this English/German
  Change Record pair.

The same PR branch also retains separately tracked Sonar-remediation changes
to CI-security and parser-hardening regression tests. This Python Change
Record does not relabel or close those distinct findings.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused Python migration contracts | `0` | 61 updater, version-contract, CI-contract, and Framework-CI-contract tests passed under the selected local CPython 3.14.4 virtual environment. | Task-owned external validation roots |
| Separately changed CI-security/parser regressions | `0` | 49 downloader, workflow-tool updater, and parser-hardening tests passed. | Task-owned external validation roots |
| Native Framework lint contract | `0` | `make lint` passed with the selected local CPython 3.14.4 virtual environment, including syntax, CI-security, workflow, provenance, documentation, catalog, and diff-hygiene checks. | Task-owned external validation roots |
| Hash-locked CP314 dependency dry run | `0` | `pip install --dry-run --ignore-installed --no-index --only-binary=:all: --require-hashes` selected the retained reviewed CP314 PyYAML wheel and would install `PyYAML-6.0.3`. | Task-owned CP314 artifact evidence |
| Pre-migration CP313 hash negative control | `1` (expected) | The deliberately retained CP313 digest rejected the CP314 artifact with a hash mismatch, proving that the old lock cannot be silently reused. | Task-owned negative fixture |
| Dependency consistency | `0` | `python -m pip check` reported no broken requirements. | Selected local virtual environment |
| Hosted initial submitted head | `1` | Run `29956021487` correctly rejected CP314 PyYAML against the trusted base's CP313-only hash lock; run `29956021568` passed lint and reported four deterministic Ruff format changes. The same head confirmed a hosted CPython 3.14.6 runtime and passed Sonar. | GitHub Actions runs `29956021487` / `29956021568`, Framework PR #42 head `e0564d219980d62bc37162ac6c11641f289f1b71` |
| Trusted-base OSV follow-up contracts | `0` | Full `make test-ci-security-contract` passed 133 tests, including missing-selector-f73 CP313, non-allowlisted-CP313 rejection, base-3.14, and obsolete PR-head-selector regressions. | Task-owned follow-up validation root |
| Deterministic Ruff follow-up | `0` | The reviewed checksum-verified Ruff 0.15.22 binary passed the exact hosted lint and format scope after formatting the four reported files. | Task-owned reviewed CI-tool extraction |
| Hosted exact source-follow-up PR checks | `0` | Exact source head `2930e04e1558b5b10bdeb87a76abb077a2085566` passed hosted `python-ci-security-quality` run `29962792445` / job `89067507532`; the repaired OSV control, all other non-skipped PR checks, and the PR SonarQube Cloud Quality Gate also passed. | GitHub Actions, GitHub PR #42 checks, and SonarQube Cloud PR #42 analysis |
| Python.org updater/network validation and resulting-master checks | `not_run` | No Python.org live updater-network run was performed. PR #42 has not merged, so no resulting-master SHA or resulting-master check exists. Every later PR head requires fresh exact-head evidence. | None |

## Security impact

This record describes a CI security-boundary migration; it does not claim a security remediation or close a finding. The required controls are preserved: exact `.python-version` selection, `check-latest: false`, immutable Action pins, hash-locked binary installation, Python.org-only/no-redirect metadata handling, fixed candidate and publisher paths, and the trusted-base OSV PR execution model. Its one SHA-bound CP313 compatibility case covers only the exact pre-selector base; it prevents a CP313/CP314 ABI mismatch without reading a PR-head Python selector. No permission expansion, mutable tag, source-build fallback, automatic merge, scanner waiver, quality-gate change, Parent change, or MRTS change is documented.

## Documentation and runtime evidence

The paired CI-security guide documents the 3.14.6 baseline, strict stable CPython 3.14 grammar, controlled candidate path, Python.org updater, publisher branch, static-tool baselines, exact CP314 PyYAML tuple, and retained OSV trust boundary including its one SHA-bound CP313 compatibility case. The README indexes this pair. Local contract and lock-dry-run evidence was collected with CPython 3.14.4; exact source follow-up `2930e04e1558b5b10bdeb87a76abb077a2085566` additionally passed hosted Python quality, repaired OSV, other non-skipped PR checks, and the PR SonarQube Cloud Quality Gate. That source-head result does not substitute for fresh evidence for a later PR head or resulting master. No connector runtime, Python.org live updater request, or real package installation was claimed.

## Checks not run

- No Python.org live request or updater-network check was run.
- No real package installation was run; the CP314 evidence uses a retained artifact and pip dry-run only.
- No local Pyright executable was installed or substituted. A retained checksum-verified Ruff binary was used only for the exact CI lint/format scope; the source follow-up's hosted Ruff and Pyright result passed, while every later PR head requires fresh hosted evidence.
- No resulting-master check has been observed because PR #42 has not merged. This record does not claim a result for a later documentation-evidence reconciliation commit.

## Limitations and residual risk

Exact source follow-up `2930e04e1558b5b10bdeb87a76abb077a2085566` proves its hosted PR event results, including Python quality, repaired OSV, other non-skipped PR checks, and the PR SonarQube Cloud Quality Gate, but it cannot prove the GitHub event context of a later PR head, `runner.temp` semantics, branch protection, or a resulting-master result. The selected local runner is CPython 3.14.4, not the configured 3.14.6. No resulting-master evidence is available. This record makes no connector-runtime claim and does not change the read-only `tools/MRTS` boundary.

## Final diff and review status

The paired documentation passed local link, variable, path-reference, Change Record, whitespace, and scoped-diff checks as part of the native lint contract. The exact source follow-up received a final-diff security review with no reportable High/Critical issue, was committed and pushed normally, and passed its hosted exact-head checks at `2930e04e1558b5b10bdeb87a76abb077a2085566`. The separate resulting-master gate review remains a delivery prerequisite, and every later PR head requires new exact-head verification. Historical Change Records are unchanged; no credential, token, raw log, or sensitive payload is recorded here.
