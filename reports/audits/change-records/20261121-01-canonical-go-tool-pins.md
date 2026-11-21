# Change record

**Language:** English | [Deutsch](20261121-01-canonical-go-tool-pins.de.md)

**Pre-publication validation snapshot.** This record captures the implemented canonical pins and the observed local checks. No hosted CI success, merge or Parent pin change is claimed.

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261121-01-canonical-go-tool-pins |
| UTC date | 2026-11-21 |
| Framework base revision | `95f228936efe17fda24f21323ad87cd698940b48` |
| Issue or pull request | Task branch `claude/go-tool-pins-20261121`; Draft pull request opened after this snapshot. |

## Motivation and problem statement

`ci/lib/common.sh` is the canonical source for every reviewed CI pin; `actionlint`, `zizmor`, `gitleaks` and the other release-asset tools are already pinned there as `CI_SECURITY_TOOL_*`. The Go analysis tools `staticcheck` and `govulncheck` had no canonical pin, so the Parent kept a separate lock for them. They cannot use the `CI_SECURITY_TOOL_*` schema because they have no release asset and SHA-256; that group validation deliberately rejects unknown or partial fields.

## Affected components and security boundaries

Only the canonical pin source, its reader and the version check change. No workflow, generated lock view, runner, fetcher or Parent file changes. The new reader parses `common.sh` with the existing trusted-path and decoding rules and never sources it.

## Acceptance criteria

Pin both Go tools in `common.sh` by exact module, package, release version and `h1:` module sum. Provide a reader that returns them keyed by executable and rejects incomplete groups, version ranges, foreign package paths, shell expressions, duplicates and groups that do not name their executable. Enforce the same group shape and component ownership in `check-common-versions.py --validate-canonical` as for the other canonical CI pins. Keep `load_canonical_ci_pins()` and every existing consumer unchanged.

## Alternatives considered

Reusing `CI_SECURITY_TOOL_*` would require placeholder asset fields or weakening the strict group validation. Extending `load_canonical_ci_pins()` would hand the new keys to its many existing consumers. A separate lock file would keep a second source of truth outside `common.sh`.

## Implementation decision

`common.sh` gains the `CI_GO_TOOL_STATICCHECK_*` and `CI_GO_TOOL_GOVULNCHECK_*` groups (`MODULE`, `PACKAGE`, `VERSION`, `MODULE_SUM`) and their export line. `common_canonical_pins.py` gains `load_canonical_go_tools()`. `check-common-versions.py` recognizes the four fields through a dedicated `CI_GO_TOOL_*` name pattern, adds the `go tool` group with its required fields and assigns the variables to the canonical CI pin component.

## Changed files and tests

- `ci/lib/common.sh`: two canonical Go tool groups and their export.
- `ci/tools/common_canonical_pins.py`: `load_canonical_go_tools()`.
- `ci/tools/check-common-versions.py`: Go tool field recognition, group shape and ownership.
- `tests/ci_security/test_common_canonical_pins.py`: eight new tests (reader result, incomplete group, range version and foreign package, shell expression and duplicate, executable naming, repository pins, inventory shape and ownership, incomplete group reporting).
- `docs/security/ci-security-tooling.md`, `docs/security/ci-security-tooling.de.md`: new section on Go tool pins.
- `connector_suite/config/testing/active-cases.json`: refreshed `common.sh` source digest through `update-inventory-bindings.py --apply`; execution selection unchanged.
- `connector_suite/reports/testing/test-selection-archive.generated.json`: regenerated through `update-test-archive.py`; on-demand definitions 8476 to 8484 (the eight new tests), new `inventory_sha256` and test source digest.
- `reports/audits/change-records/20261121-01-canonical-go-tool-pins.md` and `reports/audits/change-records/20261121-01-canonical-go-tool-pins.de.md`.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `check-common-versions.py --validate-canonical` after adding only the `common.sh` groups | 1 | `incomplete go tool group …; missing: MODULE, MODULE_SUM, PACKAGE` (fields not yet recognized) | Local Framework validation |
| `make check-canonical-common-pins` | 0 | `canonical common.sh pins: PASS` | `fwgo-20261121T093506Z` |
| `make test-canonical-pin-sync` | 0 | Python and workflow pin views unchanged | `fwgo-20261121T093506Z` |
| `python -m unittest tests.ci_security.test_common_canonical_pins` | 0 | 13 tests, including 8 new | `fwgo-20261121T093506Z` |
| `python -m unittest tests.ci_security.test_canonical_maintenance` | 0 | passed | `fwgo-20261121T093506Z` |
| `make test-ci-security-contract` | 0 | 421 tests passed in about 300 s | `fwgo-20261121T093506Z` |
| `check-common-versions.py --check`, before and after the change | 2 / 2 | identical upstream review status lines; no new finding | `fwgo-20261121T093506Z` |
| Hosted `scaffold-lint` on the first PR head, reproduced locally with `update-inventory-bindings.py --check` | 1 | `SOURCE_DIGEST_DRIFT …/ci/lib/common.sh`, `INVENTORY_BINDINGS_DRIFT`; archive check also stale | PR #182 run `44915812649` |
| `update-inventory-bindings.py --apply`, `update-test-archive.py`, then both with `--check` | 0 | `INVENTORY_BINDINGS_VERIFIED`; archive matches inventory and sources | `fwgo-20261121T093506Z` |
| Parent `make security-tools` with the same pins (Parent PR #456 helper) | 0 | `staticcheck 2026.2.2 (0.8.2)` and `govulncheck v1.10.0` built with Go 1.27.4; module sum and build information verified | Parent run `pyenv-20261119T191308Z` |

Checks used the Framework-owned virtual environment on Python `3.15.2`.

## Security impact

The Go tools gain an exact, reviewed canonical pin with a content-addressed module sum; no installation path, download, credential or permission changes in the Framework. Rejection of ranges, foreign packages and shell expressions keeps the reader as strict as the existing canonical pin parser.

## Documentation and runtime evidence

The English/German record pair and the paired security-tooling section document the same scope. No runtime evidence is collected or claimed.

## Checks not run

Hosted Framework CI, the full `lint` aggregate and a Parent consumption of these pins through a Parent gitlink update have not run for this snapshot.

## Limitations and residual risk

The Framework pins but does not build the Go tools; consumers build them with their own pinned Go toolchain. A later Go tool update follows the existing manual review of canonical CI pins.

## Final diff and review status

Local snapshot before publication; independent review pending.
