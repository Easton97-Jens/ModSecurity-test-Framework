# Connector contract tests

**Language:** English | [Deutsch](README.de.md)

## Ownership

This Framework-owned package contains the former Connector repository's Python
unit and contract tests. All tests belong to Framework, including tests of
product build/configuration, host adapters, workflows, Makefiles, source paths,
provisioning, artifacts, security and evidence. Product implementations remain
in the explicitly selected Connector checkout.

Use the unique namespace `modsecurity_connector_tests`; test orchestration uses
`modsecurity_connector_ci`, and host test adapters use `connector_suite.adapters`.
See [the interface](../../docs/connector-test-suite.md),
[source mapping](../source-map.json) and [case mapping](../test-map.tsv).

## Selection

[The inventory](../config/testing/active-cases.json) preserves the original
100 standard cases / 80 executions and 1893 on-demand cases / 839 executions.
New migration regressions remain on demand, separate from those baseline counts.
Default discovery and automatic groups select admitted standards only; more
than 100 expanded standards fails admission rather than truncating selection.
Retained specialist modules require `ON_DEMAND_TESTS=1`; the public inventory
adapter requires `--on-demand` plus an exact group/case/execution selector.

New automatically selected behavior requires a stable ID, purpose, profile and
source-bound executable selector. At capacity, identify the replaced or truly
consolidated behavior and record any lost coverage. Definitions, subtest variants,
executions, attempts and distinct cases are different counts. A retry creates no
additional distinct case. Moving a file activates no archived campaign.

## Safe execution

Connector tests require explicit product root/revision, Framework root, profile
and existing external output parent. Framework-only fixture tests must not
require an implicit parent checkout. Use the Framework-owned interpreter and
`PYTHONSAFEPATH=1`, Python `-P`, and
`PYTHONPATH="$FRAMEWORK_ROOT:$FRAMEWORK_ROOT/connector_suite"`. Product sources
are loaded through scoped explicit interfaces rather than a global product
import path. The public adapter is a source-checkout interface; installable
package coverage is a separate contract.

Keep fixtures portable, self-contained and non-secret. Do not commit runtime
output, bytecode, build/cache data, downloads, credentials or payload evidence.
Unit/contract PASS establishes only the asserted behavior; it is not hosted H1,
CRS completeness, HTTP/2, HTTP/3, production readiness or a full matrix.
The [archive generator](../modsecurity_connector_ci/tools/update-test-archive.py)
records availability without treating definitions as executed evidence.
