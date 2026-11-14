# Change record: Framework master #173 reconciliation

**Language:** English | [Deutsch](20261114-04-framework-master-173-reconciliation.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20261114-04-framework-master-173-reconciliation` |
| UTC date | 2026-11-14 |
| Framework base revision | `b0b507a58d3c763ee39b631e79282b694703d13c` |
| Integrated upstream revision | `939d1718b7548a36ff7a550080ed8b811aad8a98` (#173) |
| Issue or pull request | Framework #169 |

## Motivation and problem statement

Master advanced while #169 was being prepared. The new logical Common-source
ownership checks overlapped the external-worktree diagnostic correction, and
both branches changed the generated test archive. The PR API retained an older
base SHA; the direct master ref established the actual integration input.

## Affected components and security boundaries

This is Framework-owned checker, diagnostic-test and generated-catalog
reconciliation. Parent implementations and the MRTS pin remain unchanged.
Logical Common ownership, complete source scanning and the runtime-only
ModSecurity include exception remain enforced.

## Acceptance criteria

Preserve both branches' actual test definitions and ordering; retain 100 active
cases and 80 selectors; verify both real Git layouts and unchanged negative
controls; test the adopted contracts against an exact compatible source fixture;
retain failures from an older external consumer as separate evidence.

## Alternatives considered

Keeping one generated archive would lose legitimate definitions. Keeping
physical-only labels would contradict the new logical Common ownership model.
The native producer combines the actual source definitions instead.

## Implementation decision

The resolved Common checker is byte-identical to upstream #173. One shared
assertion in the two real-layout tests now expects the logical
`common/{directory}/{name}{suffix}` identity. All four migrated-helper
rejections per layout, Common outside-runtime denial and runtime allowance
remain unchanged. Reversing only that assertion reproduces the entire base
test file.

## Changed files and tests

The normal merge retains upstream's Apache/HAProxy adoption checks, four test
owners and paired record. This reconciliation changes the layout diagnostic
assertion and regenerates the archive from current sources. It retains all 8437
base definitions and all 8211 entries in upstream's archived view, in relative
order, and adds exactly 13 actual methods over the base. The result is 8450
definitions with no rename or deletion. Active inventory bytes are unchanged.

## Commands and results

Entrypoints below use the existing Framework Python 3.15.2 and explicitly
selected roots; exact argv and qualified logs remain private.

| Entrypoint / procedure | Exit | Result | Run reference |
| --- | --- | --- | --- |
| Normal `git merge --no-commit --no-ff` of the upstream revision | 1 | Two conflicts, resolved through reviewed source identity and native generation | master-173 reconciliation, 2026-11-14 |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_repository_architecture.RepositoryArchitectureTests` | 0 | 38 methods pass | Same run |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_repository_architecture.CommonSecurityContractLayoutTests` | 0 | Both real Git layouts pass, including retained negative controls | Same run |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_migration_source_provenance` | 0 | 9 methods pass | Same run |
| Four selected adoption/event modules against external Parent `5bab6e9d` | 1/0/1/1 | Apache suite aborts before tests; Event11 passes; HAProxy24 fails on missing product contracts | Original consumer diagnostic |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_apache_common_adoption` | 0 | 27 pass on the bound compatible fixture | Matched source fixture |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_event_runtime_security_contract` | 0 | 11 pass on the bound compatible fixture | Matched source fixture |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_haproxy_adoption_rule_id` | 0 | 12 pass on the bound compatible fixture | Matched source fixture |
| `rtk bypass python -B -P -m unittest -v modsecurity_connector_tests.test_haproxy_common_adoption` | 0 | 12 pass on the bound compatible fixture | Matched source fixture |
| Native `ci/tools/sync-maintenance-test-views.py --write`, then qualified postimages and `--check` | 0/0 | 8450 definitions; 100 cases / 80 selectors unchanged | Native view producer |

## Security impact

Scan scope, forbidden-token/function/include patterns and the logical
`common/runtime` exception are preserved. Independent source review confirmed
the exact upstream checker and one-literal test inverse. No validation, source
admission, CI requirement or Quality Gate was weakened.

## Documentation and runtime evidence

This paired record describes source and fixture evidence. The compatible
read-only fixture is external Parent #448 at
`b1017969f766209eb9401820a4aca01d71180636`, tree
`16ae9d0cea7e231f5322f3ff7ca6ebc25ddac085`. All 62 methods pass there; 138
selected source hashes remain fixed. This does not qualify Parent #445:
its original HEAD/index and the earlier failing diagnostic remain unchanged.
No SDK build, host execution or comprehensive acceptance was performed.

## Checks not run

Local Ruff/Pyright were not rerun; no tool installation is part of this change.
Hosted checks and Sonar at the resulting task/master commits are evaluated
through the existing workflows and recorded with their actual SHAs. This record
does not claim a future analysis result.

## Limitations and residual risk

A compatible-source fixture proves these Framework checks, not the older
consumer's implementation or runtime. Parent integration, final runtime evidence
and actual MRTS-main pin promotion remain independently owned work.

## Final diff and review status

The source overlap and preserved diagnostic controls passed independent review.
Native conservation checks retain both source branches' definitions. The
coordinator owns final staged whitespace/documentation checks and publishes
actual commit, CI and merge outcomes separately; none is inferred from fixtures.
