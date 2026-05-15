# V2 vs V3 Test Compatibility

Status: implemented

This document records how local ModSecurity v2 and v3 tests are reused in the
connector compatibility framework. The source trees under `/root/conecter/*`
remain read-only references.

## Source Roles

| Source | Role in this monorepo | Import rule |
| --- | --- | --- |
| `ModSecurity_V3/test/` | Primary libmodsecurity v3 API/regression reference | Source-derived YAML may enter common smoke if Apache and NGINX both pass |
| `ModSecurity_V2/tests/` | Historical semantics/regression compatibility reference | Only portable operator, transformation, rule, and collection semantics are imported |
| v2 Apache harness files | Historical connector reference | Mapped only; not used as architecture for new connectors |

## Compatibility Differences

| Area | v2 source shape | v3 source shape | Monorepo handling |
| --- | --- | --- | --- |
| Operators | Perl-style `tests/op/*.t` semantic fixtures | JSON regression cases such as `operator-rx.json` | Converted to minimal HTTP YAML when behavior is connector-neutral |
| Transformations | Perl-style `tests/tfn/*.t` fixtures | JSON transformation regressions | Converted only for text-safe cases; binary/NUL cases remain mapped |
| Request body processors | Apache regression `.t` files | JSON parser regressions | Raw JSON, simple multipart, FILES, and XML basics imported after Apache+NGINX pass |
| XML | v2 schema/DTD/parser tests | v3 `variable-XML` and parser JSON cases | Tiny XML body imported; schema/DTD/parser-error cases mapped |
| Multipart files | v2 target/multipart parser tests | v3 FILES/MULTIPART variable regressions | Deterministic small file uploads imported; malformed/streaming cases mapped |
| API smoke | v2 is not a v3 API source | v3 public C API is primary | Existing `src/v3-api-smoke` remains separate from connector `smoke-all` |
| Logging/audit | v2/v3 logs differ and include volatile fields | v3 audit/debug cases exist | Stable audit field smoke exists; debug text and complex audit variants mapped |

## Active Imports

The active V2/V3 imports are common connector tests, not copied upstream tests.
Each YAML includes provenance metadata and is executed through the same Apache
and NGINX harnesses as other common cases.

Observed locally on 2026-05-15:

| Source family | Imported active cases | Apache | NGINX |
| --- | ---: | --- | --- |
| V2 operators/transformations | 10 | pass | pass |
| V3 multipart FILES/XML/operator/action/collections/audit | 14 | pass | pass |

The second compatibility import wave intentionally used source-confirmed
values from the V2/V3 fixtures. For example, `urlDecode` uses `Test+Case` ->
`Test Case`, `htmlEntityDecode` uses the `&lt;&gt;` -> `<>` fragment, V2 `pm`
uses param `abc` with input `abcdefghi`, V2 `containsWord` uses param `abc`
with input `abc def ghi`, and V3 `pm` uses `@pm 1 2 3` with `param1=123`.
The V3 `issue-2196` `nolog,pass` case is no longer counted as an active
common import because GitHub Actions observed audit-log output while local
Apache and NGINX runs observed empty audit logs.

## Mapped Only

The following remain mapped until a future step adds dedicated support:

- XML schema/DTD validation fixtures.
- XML parser-error cases.
- Multipart malformed body and streaming/buffering edge cases.
- File-backed operators and external data files.
- Optional-library operators.
- NUL, binary, non-ASCII, and invalid-input transformation branches.
- API-only v3 tests that should run through a dedicated API smoke target rather
  than the Apache/NGINX connector smoke.
