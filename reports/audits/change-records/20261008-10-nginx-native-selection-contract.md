# Change record

**Language:** English | [Deutsch](20261008-10-nginx-native-selection-contract.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-10-nginx-native-selection-contract |
| UTC date | 2026-10-08 |
| Framework base revision | `d86894602079f4f3b5b42e076c464756c1b9031d` |

## Motivation and problem statement

The selected capability plan previously discarded the 42 native operation registrations. An input invariant must also represent 31 existing authentic executor or narrower-claim derivation contracts; assigning fake runner files would misrepresent them.

## Affected components and security boundaries

Only Framework selection helpers, select_catalog_case/select_cases and new focused controls. Existing normalization, event validation, derivation implementations, schemas and catalog remain unchanged in this slice. Parent execution and its collector are read-only dependencies. MRTS and the Parent Gitlink are unchanged.

## Acceptance criteria

Preserve the actual 97 NGX/H1 selected IDs and states, project independent copies of native/config/derived input, reject cross-case mutations and missing real sources, retain C source aliases, and preserve full-case immutable-plan comparison. Never filter a missing Required case or infer runtime PASS from dispatch input.

## Alternatives considered

Literal runner_case-only enforcement rejects legitimate native/config/derived operations. Free request.reuses inference admits undeclared substitutions and cycles. Closed function-bound descriptors describe the existing execution graph without producing requests or observations.

## Implementation decision

native_invocation_for_case validates the checked-in closed case schema before NGX projection. selected_case_invocation_errors requires matching native/config/runner/derived input for each selected NGX case. YAML alternatives must be regular catalog-local YAML files. A real manifest-declared NGX full_lifecycle plan enforces this invariant with ContractError, not a reduced plan.

Capability-only dictionaries remain advisory pure API planning inputs; they fail runtime manifest validation. Canonical select/init/finalize load validated manifests, whose connector is mandatory, and compare fresh complete selection semantics. Metadata omission therefore cannot bypass the actual runtime-plan boundary. H2/H3 advisory claims remain visible; no runtime support is promoted.

The 31 derived_invocation descriptors contain only operation, source_case_ids and mapping. Their reviewed phase, request, rule, status, result and alias inputs are closed; generic reuses alone are insufficient. Reuse cycles fail. Direct host/self IDs identify an executor leaf, not a derivation cycle. Existing selected native/config/derived dictionaries are deep-copied.

## Changed files and tests

Core selection-only helpers and two closed constant maps; new test_nginx_native_selection.py; paired record. plan_semantics needs no edit because it already retains complete case dictionaries.

| Existing boundary | Selected contracts | Actual mapping |
| --- | --- | --- |
| Parent dedicated SAFE/STRICT fixtures | core post-commit log-only and abort (2) | run_nginx_smoke.sh append_selected_phase4_fixtures; existing connector-specific YAML names match canonical IDs |
| Parent synchronized barrier | first-byte and no-full-buffer claims (2) | run-native-first-byte.sh and write-first-byte-source-results.py:main; actual real_host barrier plus rule1100301 |
| Parent strict core alias | P3 response-header core and P4 SAFE view (2) | collect-no-crs-source.py native_runner_core_case_alias; exact raw event semantics, never bare status |
| Framework event claims | five Phase1 metadata fields and Phase2 no-payload (6) | append_derived_event_records; validated source cases and actual matching events |
| Framework narrower P4 facts | observed rule, status metadata, action metadata (3) | append_derived_phase4_records; exact existing five permissible base IDs, not inverse disruptive outcome derivation |
| Framework explicit reuse | allow, deny, P3 status, response no-payload, strict abort view (5) | append_explicit_reuse_records; bound source request/TX/run/mode and event |
| Framework deprecated views | Phase1 five, Phase2 two, Phase3 one, Phase4 three (11) | resolve_deprecated_aliases; exact existing canonical target IDs |

## Commands and results

Initial projection/invariant controls failed as expected; separate derived-helper controls failed with two missing-helper errors. Twelve focused controls now pass. Existing protocol planning (4) and selected-scope tests (9) pass. The initial broad 217-test run had five synthetic capability-plan errors; distinguishing advisory planning from validated native execution fixed the affected tests. The final broad suite passed all 222 tests. Catalog-check retained 166 cases; documentation links, bilingual/variable documentation, Change Record and diff checks passed.

Fresh source-only calculation against the actual Parent capability manifest preserves 97 selected cases: 42 native and 31 existing derived descriptors. Exactly three null inputs remain in the standalone checkout: invalid_status, phase4_invalid_scope_file and phase4_wildcard_scope_rejected. Their authentic config migrations already exist in the coordinator checkout and are not modified or replaced here.

## Security impact

No invented native observations, generic expectation changes, Required reduction, fake YAML, implicit alias discovery or normalization relaxation. Native/derived mutations affect immutable plan comparison. Runtime evidence remains an independent mandatory boundary.

## Documentation and runtime evidence

Descriptors identify input and existing proof consumers only. The review read the actual Parent collector, native selected fixture mapping and synchronized writer, and Framework event/P4/reuse/deprecated implementations. No new native execution occurred.

## Checks not run

Integrated full 97-case executable plan after coordinator config3 integration, native build/runtime and final CI/Sonar remain coordinator-owned.

## Limitations and residual risk

The standalone full native plan intentionally raises for the three unintegrated config contracts. Source selection does not prove the existing derivation's required event/TX/runtime evidence. The unchanged canonical validators must still enforce it.

## Final diff and review status

Selection-only focused worktree slice; no normalizer/event/derivation implementation changes, Root worktree mutation, publication, Parent Gitlink update or MRTS changes.
