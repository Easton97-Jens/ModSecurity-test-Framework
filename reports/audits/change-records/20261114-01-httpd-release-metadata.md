# Change record: HTTPD release metadata

**Language:** English | [Deutsch](20261114-01-httpd-release-metadata.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20261114-01-httpd-release-metadata` |
| UTC date | 2026-11-14 |
| Framework base revision | `6d491b22b00ade682e8090fba0b355e0a6414ccd` |
| Issue or pull request | Framework #169; Parent #445 consumes the provisioning helper |

## Motivation and problem statement

The canonical Common contract already selects HTTPD 2.4.70. The immutable
checksum-metadata constants still selected 2.4.69, so the real production helper
rejected the current release tuple before downloading its metadata.

## Affected components and security boundaries

This Framework change covers the HTTPD checksum helper, its source-recovery
tests, the generated specialist archive and this record pair. The release,
source URL, provider, private-cache and extraction boundaries are preserved.

## Acceptance criteria

The real current-production helper selects the independently reviewed metadata
object for both CLI print modes. Mutated SHA, source, checksum, release and query
tuples remain rejected before cache I/O. All 18 previous methods and two new
methods pass; native metadata preserves 100 default cases and 80 selectors.

## Alternatives considered

Keeping the stale constants leaves the actual provisioning blocker. Bypassing
metadata verification or relaxing tuple and private-file guards is rejected.
A version upgrade is outside this correction.

## Implementation decision

Only the two production metadata constants change. The selected object is
[the immutable official 2.4.70 checksum](https://dist.apache.org/repos/dist/!svn/bc/89127/release/httpd/httpd-2.4.70.tar.bz2.sha256),
with metadata SHA256
`f412d65db7585db8e5e20e0d10dd0e6deaa6a08f52ed07bd29437777b347d29e`.
The coordinator independently checked this distribution object and the official
Apache archive checksum over verified TLS without redirects: both contain the
same 87 ASCII bytes. This is metadata evidence, not a fresh full-archive hash.

## Changed files and tests

- `ci/provisioning/httpd-checksum-cache.py`: two constants only.
- `tests/security_regression/test_httpd_source_recovery.py`: two additional
  current-contract methods without the synthetic fixture's constant projection.
- `connector_suite/reports/testing/test-selection-archive.generated.json`:
  native regeneration retains all 8325 prior definitions in order and adds two,
  giving 8327. The active inventory remains byte-identical.
- This English/German record pair follows the Framework's 13-heading template.

## Commands and results

The table names native entrypoints; the coordinating task retains the exact
argv, environment selection and qualified offline receipts.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `make test-httpd-source-recovery` | 0 | 20 methods passed, no failures, errors or skips; 93.596 seconds | HTTPD70 offline source validation, 2026-11-14 |
| Production helper CLI, both print modes | 0 / 1 | Current tuple accepted; 16 mutated-tuple controls rejected with no stdout or cache writes | Same offline run; controls are inside the two new methods |
| `ci/tools/sync-maintenance-test-views.py --write` then `--check` | 0 / 0 | Exact two generated postimages passed Secrets before freshness verification; 8327 definitions, 100 cases, 80 selectors | Same offline run |

## Security impact

No guard condition changes. Exact release/provider identity, metadata and archive
digests, private ownership, single-link files, size limits and symlink rejection
remain enforced. The production-tuple regression closes the gap left by the
older synthetic-release tests. No general vulnerability-free claim is made.

## Documentation and runtime evidence

This paired record documents the source correction and offline evidence. No
fresh Apache build, host extraction, service start, H1/CRS runtime or lifecycle
result was collected by this change. Advisory applicability remains bound to
the separately reviewed source and selected host/profile conditions.

## Checks not run

The full specialist catalogue was not repeated for this two-constant correction.
Fresh host/build/runtime validation and hosted analysis for the final combined
commit are separate coordinating-task work. No local Sonar scanner was run.

## Limitations and residual risk

Metadata admission alone does not prove archive download, compilation or host
runtime success. Future release changes require a separately reviewed metadata
object, digest and matching current-contract expectations. Final committed-pair
validation and hosted results remain pending.

## Final diff and review status

The coordinator independently approved the two-constant production diff and
focused test coverage. Source and generated outputs are handed back for scoped
review and normal delivery; the final documentation and whitespace results are
retained separately by the coordinator. This record does not claim a merge or
overall task completion.
