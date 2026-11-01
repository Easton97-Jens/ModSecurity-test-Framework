# Compiler and Apache migration-integrity follow-up

**Language:** English | [Deutsch](20261101-03-compiler-migration-integrity.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261101-03-compiler-migration-integrity |
| UTC date | 2026-11-01 |
| Framework base revision | `91f5370c7eddcebdc7e49d2099c58054ec2d5d5d` |
| Issue or pull request | Follow-up to merged Framework #148 for Parent Draft #348; new PR pending |

## Motivation and problem statement

Final integration checks exposed stale pre-migration compiler expectations and
an Apache AST golden that had not incorporated the ownership migration in #142.
These are existing-test integrity defects, not new connector-runtime findings.

## Affected components and security boundaries

Framework owns both existing test modules, source bindings and generated
inventory views. External Parent input is `b43faa78d403afd492c007e8f4a740ad21da1ac9`
with a separately owned, uncommitted compiler-generator repair. No Parent
source belongs to this Framework change. MRTS remains unchanged/read-only.

## Acceptance criteria

Retain all existing assertions, the full Apache AST guard, mutation sensitivity
and real Make-rule checks. All 44 existing methods and eight target controls
pass. Native inventory regeneration/checks and public admission preserve
selection and historical IDs. Fresh hosted follow-up verification and dependent
Parent pin remain required delivery steps.

## Alternatives considered

Do not restore deleted Parent tests, accept arbitrary targets, mock forwarding,
ignore AST nodes, accept two golden hashes or weaken provenance/gates. Update
only independently reviewed migration expectations and actual rule discovery.

## Implementation decision

Compiler checks use migrated Apache/HAProxy harness URLs and read actual
`connector_suite/connector.mk` rules only when the selected Parent Makefile
contains its explicit forwarding clause; Make assignments are not targets.

Independent reconstruction of Parent `c5993ed9` applies exactly six replacements:
the explicit `connector_context` import, `ROOT` to `connector_root()`, and
`source_path` for Apache source, documentation, architecture report and APXS
wrapper. Its output is byte-identical to the checker source since #142.
Predicates, messages, ordering and control flow are preserved. Only the reviewed
full-AST golden changes from
`2ea7f8e9c46f644deea24fe8879d7f9e30f2d820ce355302c0901779a762c49b` to
`bb412c592b9d09f7e65224a51f005c8c7f07e150cad22302e2ff7e8fcf8c7722`.

## Changed files and tests

Modify `test_compiler_guides.py` and `test_apache_common_adoption.py` under
`connector_suite/modsecurity_connector_tests/`; no new methods, cases or
selectors. Refresh one existing compiler source binding in `active-cases.json`,
then natively regenerate the selection archive and migration baseline. Retain
526 fixed Framework bindings, 235 dynamic Product sources, 100/80 standard and
2586/1140 optional cases/executions, and all 1993 baseline IDs. The paired #148
record corrects only the Go label: 1.27.3 is the selected toolchain; 1.26.9 is
the module minimum, not a toolchain pin. Versions and dependencies are unchanged.

## Commands and results

Commands use RTK, Framework Python, explicit Parent/Framework roots and external
output/temp roots. Run: `pr348-test-migration-20261101.GnuEMR`.

| Command or recorded procedure | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Compiler import before external Parent repair | 1 | Deleted provisioning path reproduced | Same run, coordinator command record |
| Existing compiler module before expectation repair | 1 | 20 pass, two stale-contract failures | Same run, coordinator command record |
| `make check-apache-common-adoption ON_DEMAND_TESTS=1` before golden repair | 2 | 21 pass, one stale-golden failure | Same run, coordinator command record |
| Existing compiler module plus eight actual target controls | 0 | All 22 methods; four valid targets accepted, four invalid names/variable rejected | `compiler-followup/compiler-tests-validation.md` contains full explicit invocation |
| Combined existing compiler/Apache modules through `python -m unittest` | 0 | 44 methods pass, 27.660s | Same run, coordinator command record |
| `make check-apache-common-adoption ON_DEMAND_TESTS=1` selecting this Framework | 0 | Native target passes after repair | Same run, coordinator command record |
| Native bindings/archive/map generation and checks | 0 | One existing binding refreshed; counts/IDs preserved | Same run, coordinator command record |
| `python -m modsecurity_test_framework.connector --check` | 0 | Public inventory admitted; not test execution | Same run, coordinator command record |
| Framework documentation scripts: `check-change-records.py`, `check-variable-documentation.py`, `check-doc-links.py`, `check-repository-path-references.py` | 0 each | Record contract; 348 tracked EN/DE pairs; links; 2153 scanned paths, zero old paths | Explicit Framework root; untracked record structure checked directly |
| `make check-documentation check-canonical-common-pins check-canonical-python-pins check-canonical-workflow-pins check-canonical-crs-contract-pins` after staging | 0 | 350 bilingual checks, links, paths, records and all four canonical pin checks pass | Explicit Framework root and Framework Python; new pair included |

An early map-generation invocation ran before the archive completed and failed
with exit 1. The correct serial regeneration and subsequent checks passed; this
ordering failure is not hidden. External Parent repair selects the moved
provisioning source with `source_path` and corrects two harness links; all 18
generated compiler guides then match tracked bytes. That repair is not part of
this Framework commit.

## Security impact

Integrity maintenance, not security remediation of a validated vulnerability.
Full AST coverage and existing mutation checks remain; no alternate hash,
ignored predicate, context bypass, compiler-warning relaxation or gate weakening.

## Documentation and runtime evidence

Update `docs/connector-test-suite.md` / `.de.md` and this paired record. Bounded
tests and static/catalog evidence do not prove live host/TLS/H2/H3 behavior.
Framework #148 is already merged at the stated base; this follow-up has no
published PR/current-head hosted evidence or merge at preparation time.

## Checks not run

Fresh follow-up hosted CI/Sonar, review and integration remain pending.
No broad qualification campaign, live TLS/H2/H3 traffic, new toolchain/version,
MRTS execution or default-suite expansion; these are outside this increment.

## Limitations and residual risk

The external Parent generator repair and exact final Framework pin are separate
required changes; Parent #348 remains Draft/unmerged. Catalog admission does
not execute cases or resolve the broader original protocol qualification.

## Final diff and review status

Task-owned Framework preparation; staged whitespace, independent bounded
code/catalog review and independent EN/DE review pass. Twenty-six isolated
Make-parser probes preserve exact-target and assignment boundaries; this is
static discovery, not Make execution. Fresh hosted verification remains pending.
Documentation contains only safe summaries and
reviewed hashes, not secrets, raw bodies, credentials or full environment dumps.
