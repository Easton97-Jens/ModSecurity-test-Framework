# PR #70 Audit Phase Coverage Plan

**Language:** English | [Deutsch](pr70-audit-phase-coverage-plan.de.md)

Status: partially implemented

This document records how upstream ModSecurity-apache PR #70 should be mapped
into this external test framework. It is a framework-local plan only. It does
not change connector source, Apache or NGINX runtime semantics, submodule
references, or RESPONSE_BODY promotion status.

Upstream PR: https://github.com/owasp-modsecurity/ModSecurity-apache/pull/70

Observed PR head: `73c4ae80743810d866771dd4183be2bea44947dd`

## Upstream PR Summary

PR #70 is an Apache::Test harness change titled "Enable audit log and add
00-phases tests". The pull request body describes this as stage 1 of converting
automated tests for the libmodsecurity Apache connector, with two goals:

- enable examination of the audit log in automated tests
- add the first batch of automated tests, specifically the five phases tests

The PR changes nine files:

| path | upstream role | framework decision |
| --- | --- | --- |
| `Makefile.am` | Adds a `-postamble` that turns `SecAuditEngine On` on for Apache::Test. | Do not copy. The external framework keeps audit directives in YAML case `rules` with per-case log placeholders. |
| `t/00-phases.t` | Adds five Perl tests that inspect the Apache audit log after each request. | Map behavior into YAML only after stable connector-neutral assertions are defined. |
| `t/conf/extra.conf.in` | Adds global serial audit log directives and five Apache `<Location>` blocks with phase-specific rules. | Use as source evidence only. Do not move Apache `<Location>` config into shared cases. |
| `t/find_string_in_file.pl` | Reads only newly appended audit-log bytes and regex-matches expected strings. | Prefer the existing Python runner and normalizer path. |
| `t/htdocs/00-phases/00-phases_01.html` | Static response fixture for phase 1. | Use YAML `response.body` if a derived case needs fixture content. |
| `t/htdocs/00-phases/00-phases_02.html` | Static response fixture for phase 2. | Same as above. |
| `t/htdocs/00-phases/00-phases_03.html` | Static response fixture for phase 3. | Same as above. |
| `t/htdocs/00-phases/00-phases_04.html` | Static response fixture for phase 4. | Do not use as verified RESPONSE_BODY evidence. |
| `t/htdocs/00-phases/00-phases_05.html` | Static response fixture for phase 5. | Keep phase 5 as plan-only until the framework has explicit capability and assertion semantics. |

Upstream audit configuration uses serial audit logging and broad audit parts:

```apache
SecAuditEngine On
SecAuditLog @ServerRoot@/logs/audit_logs.txt
SecAuditLogParts ABIJDEFHZ
```

The external framework already uses the safer per-case form in YAML:

```apache
SecAuditEngine RelevantOnly
SecAuditLogType Serial
SecAuditLogParts ABHZ
SecAuditLog "@@AUDIT_LOG@@"
SecAuditLogStorageDir "@@AUDIT_LOG_DIR@@"
```

That existing pattern should remain the default for portable coverage because
the runner materializes per-case log paths and assertions check only stable
substrings.

## Existing Framework State

The current framework already has the right ownership boundary:

- YAML cases live under `tests/cases/`.
- Python runner and materializer code lives under `tests/runners/`.
- Normalizers live under `tests/normalizers/`.
- There are no active Perl `.t` runtime tests in the framework case corpus.
- Apache and NGINX runtime execution stays in connector-aware smoke scripts.
- Audit-log cases are expressed as YAML `expect.audit_log` substring checks.

Relevant existing coverage:

| area | current status |
| --- | --- |
| phase 1 | Existing active/imported YAML cases under `tests/cases/phases/phase1/` and request-header cases. |
| phase 2 | Existing active/imported YAML cases under `tests/cases/phases/phase2/`, including query args and request body. |
| phase 3 | Existing response-header YAML cases under `tests/cases/response/headers/`; many edge cases remain former expected-failure. |
| phase 4 | Existing response-body YAML probes are former expected-failure, future, connector-gap, experimental, or pass-through only. RESPONSE_BODY remains non-verified and non-promoted. |
| phase 5 | No framework capability exists yet for `phase5`; no active YAML cases use `phase:5`. |
| audit log | Existing serial audit-log YAML cases under `tests/cases/audit-log/`; stable checks are substring based. |
| request body | Existing active/imported raw request-body, JSON, XML, multipart, and URL-encoded cases. |
| response body | Existing pass-through and former expected-failure probes only; no verified blocking promotion. |

The audit normalizer is intentionally skeletal. It normalizes timestamps, PIDs,
thread IDs, localhost ports, and transaction IDs, but it does not parse audit
sections, canonicalize header order, or reconcile Apache/NGINX audit-format
differences. Broad audit-log comparison must remain deferred until that exists.

## Import Plan

### Minimal First 00-phases Group

Create a small source-derived `00-phases` group only after the runtime
expectations can be expressed with existing stable fields:

| phase | initial target | expected classification |
| --- | --- | --- |
| phase 1 | Request-line or request-header rule. Audit log should include the phase-1 rule message and should not require request-body, response-header, or response-body details. | active/imported candidate after Apache and NGINX pass. |
| phase 2 | URL-encoded request-body or ARGS rule, using existing `request_body` and `form_urlencoded` support. | active/imported candidate if both connectors already pass the existing request-body smoke path. |
| phase 3 | Basic `RESPONSE_HEADERS` rule against a stable emitted header. | keep active only if existing `response_header_basic` remains stable; otherwise former expected-failure/runtime-difference. |
| phase 4 | `RESPONSE_BODY` evidence only. | former expected-failure, mapped-only, connector-gap, or deferred. Do not promote RESPONSE_BODY. |
| phase 5 | Logging-phase observation. | plan-only until `phase5` is added as a known capability and the runner has stable assertions. |

The first implementation should not copy the upstream Perl file. It should add
small YAML cases or fixtures under `tests/cases/` only where the existing schema
can express the request, response fixture, rules, and expected artifacts.

### Audit Log Assertions

Use per-case audit-log files rather than a shared appended log:

- Keep `SecAuditEngine RelevantOnly` for blocking/auditlog probes unless a
  specific case requires `On`.
- Keep `SecAuditLogType Serial`.
- Prefer `SecAuditLogParts ABHZ` for stable checks.
- Write logs through `@@AUDIT_LOG@@` and `@@AUDIT_LOG_DIR@@`.
- Assert only stable substrings such as rule id, request URI, and message.
- Avoid asserting full audit sections, timestamps, transaction IDs, dynamic
  paths, server banners, local ports, or header ordering.

Additional normalizer work should precede any broad audit comparison:

- section-aware serial audit parser
- transaction-id replacement for all observed formats
- absolute path replacement for generated runtime roots
- Apache/NGINX header-order and casing policy
- connector-specific formatting handled outside common assertions

### Connector Matrix

| connector | phase 1 | phase 2 | phase 3 | phase 4 | phase 5 | audit log |
| --- | --- | --- | --- | --- | --- | --- |
| Apache | expected pass after source-built smoke proof | expected pass where request-body support is already proven | expected pass only for stable header fixture | deferred/former expected-failure until RESPONSE_BODY blocking is proven | deferred | expected pass only for stable serial substrings |
| NGINX | expected pass after source-built smoke proof | expected pass where request-body support is already proven | expected pass only for stable header fixture | depends on existing NGINX phase-4 capability status; log-only evidence is not RESPONSE_BODY promotion | deferred | expected pass only for stable serial substrings |

The matrix is evidence-driven. Generated reports and YAML metadata do not
promote former expected-failure, mapped-only, future, connector-gap, or RESPONSE_BODY cases.

## Non-Goals

- Do not update `/root/conecter/ModSecurity-conector`.
- Do not update submodules or connector source references.
- Do not change Apache or NGINX runtime configuration globally.
- Do not copy Apache::Test Perl `.t` files into the common runtime path.
- Do not add broad CRS regression coverage.
- Do not assert complete audit-log equality before normalizer support exists.
- Do not promote RESPONSE_BODY or phase-4 blocking based on PR #70.

## Safe Next Step

The first source-derived YAML group is implemented under
`tests/cases/audit-log/pr70-phases/`:

| case | phase | status | intent |
| --- | --- | --- | --- |
| `pr70_phase1_audit_request_header` | 1 | imported | request-header phase-1 rule plus stable serial audit substrings |
| `pr70_phase2_audit_urlencoded_body` | 2 | imported | URL-encoded request-body/ARGS phase-2 rule plus stable serial audit substrings |
| `pr70_phase3_audit_response_header` | 3 | imported | static-file response-header phase-3 rule plus stable serial audit substrings |
| `pr70_phase4_response_body_audit_xfail` | 4 | imported | RESPONSE_BODY audit probe kept non-promotable; former expected-failure history is metadata only |

Phase 5 remains deferred because the framework does not yet have a `phase5`
capability or stable logging-phase assertion model.
