# Change record: align adoption checks and regenerate the retained test archive

**Language:** English | [Deutsch](20261114-02-fzipi-test-archive.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261114-02-fzipi-test-archive |
| UTC date | 2026-11-14 |
| Framework base revision | `2cc331d8bc4c86592afd7219ddeaba1e60dc0ced` |
| Issue or pull request | Separate Framework delivery pending |

## Motivation and problem statement

The native Connector inventory aggregate rejected its stale retained-definition
archive. After regeneration, complete `quick-check` exposed two stale adoption
contracts: Apache still required an artificial response `SIZE_MAX` delivery bound,
and HAProxy expected the Rule-ID decoder in the old inline collector rather than
the extracted details helper. The HAProxy mutation fixtures also inherited the
real checkout context instead of selecting their isolated mutated repository.
A later full run also exposed a Common security-check path assumption: four
source-map-selected Framework files were incorrectly made relative to Parent.

## Affected components and security boundaries

Framework-owned Apache/HAProxy static checks, the Common security checker, their four test modules,
the generated archive and this EN/DE pair change. Parent product source, active
inventory, selectors, generators, CI gates and MRTS remain unchanged. The active
automatic inventory remains exactly 100 cases. This does not promote host support.

## Acceptance criteria

Accept the actual saturating observation and checked native capture paths;
reject counter, pointer, native-result, cleanup and decision-reset mutations;
bind mutation fixtures to their exact isolated Git revision; regenerate the
archive canonically; verify native aggregates and documentation before delivery.

## Alternatives considered

Restoring the response `SIZE_MAX` bound would contradict the product requirement.
Broad token acceptance would miss dead code and resets. A manual archive hash edit
would omit stale source/definition projections. Keep the existing native gates.

## Implementation decision

Apache replaces only the obsolete response-bound operand with a strict complete,
comment-masked helper-body comparison. Both saturating counters, data/invariant
checks, full native append and intervention capture must remain on the live path.
All other predicates/messages/order and request arithmetic checks are preserved.
The reviewed normalized AST anchor is updated explicitly; negative mutations cover
unchecked/lossy counters, altered guards and foreign/comment/dead-code decoys.

HAProxy retains the exact bounded decoder and checks complete collector and details
bodies, including positive native-result dispatch, actual intervention forwarding,
action/status classification and cleanup. Mutation controls reject `init_decision`,
`memset`, direct Rule-ID writes, early returns and enforcement bypasses after decode.
Both HAProxy fixture modules use the existing committed `fixture_environment` and
required `common/include` marker. These are strict static source contracts, not a
general C reachability proof or host runtime evidence.

The Common security checker retains the complete original physical scan list and
all security predicates. It carries logical Common IDs alongside selected physical
paths, preserving the `common/runtime`-only host API include exception. Four split-
owner regressions reject forbidden includes/calls in both owners and reproduce the
original ValueError with the old operand. The full 11-test module and actual native
security target pass. No file is skipped because it belongs to Framework.

After freezing all source edits, run the existing archive generator without
`--check`. Compared with the base: definitions 8096 → 8211, sources 643 → 648,
no source removals or selected-definition membership changes; 30 existing source
entries refresh their projections. Nine native source hashes refresh; their count
remains 88. Inventory digest becomes `bf346309d75aaf0aa15c0c5939b35b2caed38754f6180ac9fd5c051485be632c`.
All other top-level fields remain identical. Full keyed values are external in
`semantic-delta-integrated.json`. Archive SHA-256 becomes
`4cf2c73b5aee0d163c4f7bb4d2a049ae643caa7907da240819728709abea3b24`.
The source-binding updater reports VERIFIED; no active-inventory edit is needed.

## Changed files and tests

Two adoption-check files, the Common security checker,
`test_event_runtime_security_contract.py`, `test_apache_common_adoption.py`,
`test_haproxy_adoption_rule_id.py`, `test_haproxy_common_adoption.py`, the generated
`connector_suite/reports/testing/test-selection-archive.generated.json` and this
record pair. Tests remain in `connector_suite/modsecurity_connector_tests/`.
No product, generator, extraction-manifest, selector or MRTS change.

## Commands and results

`$PYTHON` is the Framework-owned `$VIRTUAL_ENV/bin/python`.
`$R` is `$CODEX_TEMP_ROOT/runs/20261114-fzipi-review/framework-archive-remediation`;
`$F` and `$P` are the task Framework and Parent worktrees under
`$CODEX_TEMP_ROOT/worktrees/`. External Parent revision:
`b1017969f766209eb9401820a4aca01d71180636`.
Native orchestration actually enters through `rtk bypass python3`, then
`rtk bypass bash -c` sourcing `$R/context.sh`, then the RTK child commands below.
Context supplies explicit Framework/Connector roots, exact Parent revision,
profile `h1`, external output/build/temp/log roots, Framework PYTHONPATH and no
`ON_DEMAND_TESTS` for native defaults. Focused modules explicitly set it to `1`.

| Child command or observed check | Exit | Result / evidence |
| --- | --- | --- |
| Native inventory aggregate / archive `--check`, before repair | 2 / 1 | Stale archive reproduced |
| Apache focused common/native adoption modules | 0 | 36 tests; external `framework-apache-contract/focused-tests.log` |
| `rtk bypass "$PYTHON" -m unittest -v modsecurity_connector_tests.test_haproxy_adoption_rule_id modsecurity_connector_tests.test_haproxy_common_adoption` | 0 | 24 tests; external `framework-haproxy-contract/focused-final-combined.log` |
| `rtk bypass "$PYTHON" -P connector_suite/modsecurity_connector_ci/tools/update-inventory-bindings.py --check` | 0 | INVENTORY_BINDINGS_VERIFIED; `$R/logs/bindings-final.log` |
| `rtk bypass "$PYTHON" -P connector_suite/modsecurity_connector_ci/tools/update-test-archive.py`, then `--check` | 0 / 0 | Canonical generation / exact verification |
| `rtk make check-active-inventory` from `$P` | 0 | Complete aggregate; `$R/logs/inventory-final.log` |
| First full `rtk make quick-check` after checker alignment | 2 | Passed source checks; Apache compiler output default was outside writable roots |
| Rerun with `APACHE_C_STANDARDS_OUT=$BUILD_ROOT/apache-c-standards` | 2 | All connector adoption/C17 steps passed; exposed split-source Common path error |
| `rtk make check-common-security-contract` | 0 | Full native checker after source identity fix |
| `ON_DEMAND_TESTS=1 rtk bypass "$PYTHON" -m unittest -v modsecurity_connector_tests.test_event_runtime_security_contract` | 0 | Full module: 11 tests |
| Final `rtk make quick-check` with external Apache output | 0 | Complete ordered lint and quick-check; `$R/logs/quick-integrated.log` |
| Remaining 13 lint targets and six tail checks, isolated preflight | 0 each | External `remaining-lint-preflight/` and `remaining-lint-tail/` |
| `rtk make check-documentation` / `rtk bypass git diff --check` | 0 / 0 | Observed preparation checks; repeated before publication |
| `rtk bypass /usr/local/bin/sonar-with-env analyze secrets --stdin` | 0 | Selected complete sources/records and entire 1602900-byte final archive; logs checked in bounded overlapping chunks |

## Security impact

Strengthens validation of real counter/native-decision paths and restores mutant
fixture isolation. No rule suppression, weaker warning, gate change or additional
WAF bypass. Secrets passes certify only the selected inputs, not complete quality.

## Documentation and runtime evidence

This EN/DE pair records Framework repair. Parent checks are explicitly external
integration evidence. No new host runtime, promotion or merge result is claimed.
Parent gitlink: `unchanged` at preparation; follow-up integration is separate.
MRTS: `default_read_only`; no initialization, update or checkout.

## Checks not run

New host runtime qualification is outside this Framework contract repair. Hosted
CI and the current-head Quality Gate remain required for separate PR delivery.
No packages or toolchains are installed.

## Limitations and residual risk

The archive describes availability; 8211 definitions are not 8211 executed tests.
Exact structural checks intentionally reject unreviewed source refactoring and
must evolve with tested product contracts. Native static checks do not establish
all-host runtime support. The passing local run used the frozen Framework working tree at base `2cc331d8`
against external Parent `b1017969`; PR CI and its current-head gate remain separate.

## Final diff and review status

Apache/HAProxy and Common identity diffs independently reviewed. Focused
positive and negative tests pass: 71 focused tests across the affected modules,
plus complete native quick-check. PR delivery and Parent integration remain
separate; neither is claimed here.
