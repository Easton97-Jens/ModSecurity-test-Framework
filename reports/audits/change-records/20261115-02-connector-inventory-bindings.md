# Change record

**Language:** English | [Deutsch](20261115-02-connector-inventory-bindings.de.md)

**Pre-publication validation snapshot.** Delivery identity and current hosted CI are tracked separately. No Framework merge or Parent pin change is claimed.

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261115-02-connector-inventory-bindings |
| UTC date | 2026-11-15 |
| Framework base revision | `2b56f868fc7fcecbd78c15860b59604c3c63870c` |
| Issue or pull request | No pull request at this local validation snapshot; task branch `codex/repair-updater-source-bindings`. |

## Motivation and problem statement

Parent updater run `43717327488` remained blocked after its earlier updater repair. The public Framework inventory CLI reproduced `ACTIVE_INVENTORY_REJECTED` for `connectors/traefik/harness/i12/native/client.py`. The canonical Linux binding-owner check identified ten stale source bindings.

## Affected components and security boundaries

This Framework-only change repairs inventory-to-source integrity and adds a Framework-owned lint check. Parent files, its Framework gitlink and MRTS are unchanged. Exact source-binding validation remains enforced; no runtime or connector qualification is inferred.

## Acceptance criteria

The public inventory check must accept the reviewed source bindings with `active_case_count=100` and `selected_executions=80`. Case selectors must remain unchanged. Generated archive data must agree with its native owner, and independent Framework lint must reject future binding/archive drift without requiring a product checkout.

## Alternatives considered

Disabling the binding check or changing case selection would hide drift and alter coverage. Hand-editing generated archive bytes would bypass its owner. Refresh only reviewed digests with the canonical owner and regenerate the archive through its native generator.

## Implementation decision

Independent static review of all ten source differences found no issue: two Traefik client guards, three lighttpd JSON path boundaries, a no-op `common.sh` case and NGINX runner refactors. `update-inventory-bindings.py --apply` updated ten hash slots. Active selectors, 100 cases and 80 executions are unchanged. `update-test-archive.py` regenerated the archive; its changed fields are `inventory_sha256`, `on_demand_definition_count` and `sources`, all owned by that generator. No new default execution is introduced. Framework lint now runs the binding and archive owners in check mode with read-only GitHub contents permission and no product dependency, before the existing Framework lint step.

## Changed files and tests

- `.github/workflows/lint.yml`: independent binding/archive drift check.
- `connector_suite/config/testing/active-cases.json`: ten reviewed source-hash slots.
- `connector_suite/reports/testing/test-selection-archive.generated.json`: native generated archive update.
- `reports/audits/change-records/20261115-02-connector-inventory-bindings.md` and `reports/audits/change-records/20261115-02-connector-inventory-bindings.de.md`: this paired record.

All six existing binding/archive maintenance tests passed (exit 0, 0.084 seconds). Independent source comparison proved exactly ten canonical Git-source hash changes, all 529 source paths preserved and every non-binding inventory field unchanged. No new active cases are added.

Three existing core inventory regressions also passed (exit 0, 0.276 seconds): changed source bytes prevent execution, inventory overflow is rejected before a child starts, and case selection closes over execution variants.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `/var/tmp/codex/ModSecurity-test-Framework/venv/bin/python -B -m modsecurity_test_framework.connector --check`, before repair | 1 | Reproduced `ACTIVE_INVENTORY_REJECTED` at the Traefik client binding. | Parent run `43717327488` |
| `python -B "$TEST_ROOT/connector_suite/modsecurity_connector_ci/tools/update-inventory-bindings.py" --check`, canonical Linux source | 1 | Ten stale bindings. | Local Framework validation |
| `update-inventory-bindings.py --apply` | 0 | Ten source-hash slots updated; selectors unchanged. | Local Framework validation |
| `update-inventory-bindings.py --check`, after repair | 0 | `INVENTORY_BINDINGS_VERIFIED`. | Local Framework validation |
| `update-test-archive.py` | 0 | Archive regenerated through its native owner. | Local Framework validation |
| `update-test-archive.py --check` | 0 | Archive matches generator inputs. | Local Framework validation |
| `/var/tmp/codex/ModSecurity-test-Framework/venv/bin/python -B -m modsecurity_test_framework.connector --check`, after repair | 0 | `active_case_count=100`, `selected_executions=80`. | Local Framework validation |
| Six existing binding/archive maintenance tests | 0 | Six tests passed in 0.084 seconds. | Local Framework validation |
| Three selected `ActiveTestInventoryTests` for source-digest rejection, overflow rejection and closed case selection | 0 | Three tests passed in 0.276 seconds. | Local Framework validation |
| `verify_framework_inventory.py` | 0 | Exactly ten canonical binding changes; 529 paths and all non-binding fields preserved; 100 cases / 80 executions unchanged. | External task verification artifact |
| YAML parsing and `bash -n` on the new lint `run` block | 0 | Exactly two `--check` calls, no `--apply`, before existing Framework lint. | Local Framework validation |

Checks used the Framework virtual environment on existing WSL Python `3.13.7`. A native Linux checkout with LF bytes was required: Windows CRLF materialization produced 529 false drift signals, and the Windows worktree Git path was incompatible with WSL. The task-owned native clone did not initialize MRTS.

The explicit public-CLI context selected Parent revision `ab7a32ab464a3dd8fe119b10d3936acd4b4ae557`, the native Framework checkout through `TEST_ROOT` and `PYTHONPATH`, profile `h1`, and a task-owned external output root. `PYTHONNOUSERSITE=1` and `PYTHONDONTWRITEBYTECODE=1` were set. Source-owner commands used the same Framework-owned interpreter and exact native checkout.

## Security impact

No security remediation is claimed. The inventory still rejects mismatched source bytes; only independently reviewed hashes were refreshed. Read-only lint checks detect future drift. No permission, scanner, quality gate or runtime trust boundary was weakened.

## Documentation and runtime evidence

This English/German record pair documents the same scope, facts and limitations. No connector runtime or lifecycle evidence was collected. Passing inventory validation proves source-binding and selection consistency only.

## Checks not run

Canonical Python `3.15` CI, the complete hosted Parent updater, full `quick-check` and native runtime execution have not been demonstrated locally. Product builds, connector runtime matrices and MRTS execution are outside this Framework maintenance scope. Final record-schema and diff checks are recorded separately after the last documentation edit.

## Limitations and residual risk

Source hashes prove byte identity, not runtime correctness. Future source changes must use the binding owner and archive generator; lint should expose omitted refreshes. This pre-publication snapshot does not assert delivery identity or hosted CI success. Framework delivery remains separate; no Framework merge or Parent gitlink update is claimed.

## Final diff and review status

All ten source differences received independent static review without findings. Six maintenance tests, post-repair binding validation, archive check, independent inventory comparison and CI-block syntax/placement checks passed. Final edited-byte Secrets scans, record-schema checks and whitespace/diff review are performed separately after this final documentation edit. Framework delivery remains separate from Parent and MRTS delivery; this record claims no merge or Parent pin change.
