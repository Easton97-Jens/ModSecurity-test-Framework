# Upstream Pruning Analysis

**Language:** English | [Deutsch](upstream-pruning-analysis.de.md)

Status: implemented

This document records the pruning review for the controlled Apache and NGINX
connector source imports. The review is intentionally conservative: files are
removed only when they have a functional replacement, are not required for
license or origin context, and have a successful isolated `$BUILD_ROOT` probe.
Phase 4 removed one NGINX debug helper after adding a repo-owned build-copy
overlay. Phase 5 reviewed the remaining source helpers and found no additional
safe replacement candidate. Phase 9 moved NGINX `config` and module source
files into adapter-owned `connectors/nginx/src/`. Phase 10 removed the
remaining NGINX `upstream/` attribution-only tree after durable attribution was
confirmed in `licenses/nginx/`, `connectors/nginx/ORIGIN.md`, and
`connectors/nginx/SOURCE_MAP.json`. Phase 11 moved Apache source and
Autotools/APXS inputs into adapter-owned `connectors/apache/src/`, proved a
materialized build plus real-world Apache smoke, and removed the former Apache
`upstream/` reference tree.

Phase 8 adds a shadow build-source layer. The monorepo-default NGINX build now
uses `$BUILD_ROOT/nginx-build/connector-src`, originally generated from the
remaining imported upstream source plus adapter-owned overlays. Phase 8 itself
was not a new pruning event.

Phase 10 changes that build-copy composition again: the NGINX module source and
`config` are adapter-owned, and NGINX no longer contributes
`upstream-derived` files to the materialized source manifest.

Phase 13 simplifies the repository layout without changing the materialized
build layout: Apache build files move to `connectors/apache/`, Apache C files
are flattened under `connectors/apache/src/`, Apache templates move under
`tests/cases/connector-specific/apache/`, and NGINX `config` moves to `connectors/nginx/config`.

## Evidence Used

- File inventory from the former `connectors/apache/upstream/`, former
  `connectors/nginx/upstream/`, and current `connectors/apache/` and
  `connectors/nginx/`.
- Apache Autotools inputs: `configure.ac`, `Makefile.am`, `build/*.m4`, and
  `build/apxs-wrapper.in`.
- NGINX module metadata before phase 9:
  `connectors/nginx/upstream/config`.
- NGINX adapter-owned module metadata after phase 9:
  `connectors/nginx/config`.
- Current smoke harness behavior in `modules/ModSecurity-test-Framework/ci/provisioning/prepare-apache-build.sh` and
  `modules/ModSecurity-test-Framework/ci/provisioning/prepare-nginx-build.sh`.
- Existing real-world smoke path, which materializes connector source trees
  under `$BUILD_ROOT` before building.

## Result

| Connector | Imported files before reduction | Removed after phase 4 | Removed after phase 5 | Removed after phase 9 | Removed after phase 10 | Removed after phase 11 | Reason |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Apache | 25 | 0 | 0 | 0 | 0 | 25 | Source, Autotools inputs, templates, and attribution moved to adapter-owned `connectors/apache/src`; durable attribution remains under `licenses/apache/` |
| NGINX | 12 | 1 | 0 | 7 | 4 | 0 | `src/ddebug.h` was replaced by repo-owned `connectors/nginx/src/ddebug.h`; NGINX `config` and six module source/dependency files moved to adapter-owned `connectors/nginx/src`; final attribution files moved to durable `licenses/nginx/` |

The imported trees have been retired. Apache and NGINX no longer keep local
`connectors/*/upstream/` trees; productive connector source is adapter-owned
and tracked by `connectors/apache/SOURCE_MAP.json` and
`connectors/nginx/SOURCE_MAP.json`.
Phase 5 intentionally did not delete another file because the reviewed
candidates were production request/response, config, lifecycle, or audit paths.

## Apache File Classification

Source: former `connectors/apache/upstream/`; current adapter-owned source root:
`connectors/apache/` plus durable attribution in `licenses/apache/`.

| File | Classification | Evidence | Decision |
| --- | --- | --- | --- |
| `AUTHORS` | documentation-only | Upstream attribution required for controlled import | Removed from upstream tree in phase 11 and from `connectors/apache/src/` in phase 12; durable copy remains at `licenses/apache/AUTHORS` |
| `CHANGES` | documentation-only | Upstream change context retained with imported source | Removed from upstream tree in phase 11 and from `connectors/apache/src/` in phase 12; durable copy remains at `licenses/apache/CHANGES` |
| `LICENSE` | documentation-only after phase 12 | License text is retained centrally; `configure.ac` now uses `AC_CONFIG_SRCDIR([src/mod_security3.c])` | Removed from upstream tree in phase 11 and from `connectors/apache/src/` in phase 12; durable copy remains at `licenses/apache/LICENSE` |
| `README.md` | documentation-only | Upstream build context replaced by repo-owned connector documentation | Removed from upstream tree in phase 11 and from `connectors/apache/src/` in phase 12; current overview is in `connectors/apache/README.md` and docs |
| `Makefile.am` | required | Automake input for connector build | Moved to `connectors/apache/Makefile.am` |
| `autogen.sh` | build-only | Bootstraps Autotools files in build copy | Moved to `connectors/apache/autogen.sh` |
| `configure.ac` | required | Defines build checks and generated templates | Moved to `connectors/apache/configure.ac` |
| `build/apxs-wrapper.in` | build-only | APXS wrapper template used by Autotools build | Moved to `connectors/apache/build/apxs-wrapper.in` |
| `build/ax_prog_apache.m4` | build-only | Apache detection macro | Moved to `connectors/apache/build/ax_prog_apache.m4` |
| `build/find_apxs.m4` | build-only | APXS detection macro | Moved to `connectors/apache/build/find_apxs.m4` |
| `build/find_libmodsec.m4` | build-only | libmodsecurity detection macro | Moved to `connectors/apache/build/find_libmodsec.m4` |
| `src/mod_security3.c` | required | Apache module entrypoint | Moved to `connectors/apache/src/mod_security3.c` |
| `src/mod_security3.h` | required | Apache module declarations | Moved to `connectors/apache/src/mod_security3.h` |
| `src/msc_config.c` | required | Apache directive/configuration implementation | Moved to `connectors/apache/src/msc_config.c` |
| `src/msc_config.h` | required | Apache configuration declarations | Moved to `connectors/apache/src/msc_config.h` |
| `src/msc_filters.c` | required | Apache input/output filter implementation | Moved to `connectors/apache/src/msc_filters.c` |
| `src/msc_filters.h` | required | Apache filter declarations | Moved to `connectors/apache/src/msc_filters.h` |
| `src/msc_utils.c` | required | Apache connector utility implementation | Moved to `connectors/apache/src/msc_utils.c` |
| `src/msc_utils.h` | required | Apache connector utility declarations | Moved to `connectors/apache/src/msc_utils.h` |
| `t/conf/extra.conf.in` | build-only | Keeps upstream `t/conf` test-template layout; references generated `modules.conf` | Moved to `tests/cases/connector-specific/apache/t/conf/extra.conf.in` |
| `tests/run-regression-tests.pl.in` | build-only | Listed in `configure.ac` `AC_CONFIG_FILES` | Moved to `tests/cases/connector-specific/apache/run-regression-tests.pl.in` |
| `tests/regression/misc/40-secRemoteRules.t.in` | build-only | Listed in `configure.ac` `AC_CONFIG_FILES` | Moved to `tests/cases/connector-specific/apache/regression/misc/40-secRemoteRules.t.in` |
| `tests/regression/misc/50-ipmatchfromfile-external.t.in` | build-only | Listed in `configure.ac` `AC_CONFIG_FILES` | Moved to `tests/cases/connector-specific/apache/regression/misc/50-ipmatchfromfile-external.t.in` |
| `tests/regression/misc/60-pmfromfile-external.t.in` | build-only | Listed in `configure.ac` `AC_CONFIG_FILES` | Moved to `tests/cases/connector-specific/apache/regression/misc/60-pmfromfile-external.t.in` |
| `tests/regression/server_root/conf/httpd.conf.in` | build-only | Listed in `configure.ac` `AC_CONFIG_FILES` | Moved to `tests/cases/connector-specific/apache/regression/server_root/conf/httpd.conf.in` |

## NGINX File Classification

Source: former `connectors/nginx/upstream/`; current source root:
`connectors/nginx/` plus durable attribution in `licenses/nginx/`.

| File | Classification | Evidence | Decision |
| --- | --- | --- | --- |
| `AUTHORS` | documentation-only | Upstream attribution required for controlled import | Removed from `connectors/nginx/upstream/`; durable copy remains at `licenses/nginx/AUTHORS` |
| `CHANGES` | documentation-only | Upstream change context retained with imported source | Removed from `connectors/nginx/upstream/`; durable copy remains at `licenses/nginx/CHANGES` |
| `LICENSE` | required | License text for Apache-2.0 imported files | Removed from `connectors/nginx/upstream/`; durable copy remains at `licenses/nginx/LICENSE` |
| `README.md` | documentation-only | Upstream build and usage context | Removed from `connectors/nginx/upstream/`; origin context remains in `connectors/nginx/ORIGIN.md` and docs |
| `config` | replaced | NGINX module build metadata now lives at `connectors/nginx/config` | Removed from upstream after phase 9 smoke validation |
| `src/ngx_http_modsecurity_access.c` | replaced | Adapter-owned copy now lives at `connectors/nginx/src/ngx_http_modsecurity_access.c` | Removed from upstream after phase 9 smoke validation |
| `src/ngx_http_modsecurity_body_filter.c` | replaced | Adapter-owned copy now includes PR #377 source changes | Removed from upstream after phase 9 smoke validation |
| `src/ngx_http_modsecurity_common.h` | replaced | Adapter-owned copy now includes PR #377 source changes | Removed from upstream after phase 9 smoke validation |
| `src/ngx_http_modsecurity_header_filter.c` | replaced | Adapter-owned copy now lives at `connectors/nginx/src/ngx_http_modsecurity_header_filter.c` | Removed from upstream after phase 9 smoke validation |
| `src/ngx_http_modsecurity_log.c` | replaced | Adapter-owned copy now lives at `connectors/nginx/src/ngx_http_modsecurity_log.c` | Removed from upstream after phase 9 smoke validation |
| `src/ngx_http_modsecurity_module.c` | replaced | Adapter-owned copy now includes PR #377 source changes | Removed from upstream after phase 9 smoke validation |

## Replaced Files

| File | Previous classification | Replacement | Evidence | Decision |
| --- | --- | --- | --- | --- |
| `connectors/nginx/upstream/src/ddebug.h` | build dependency | `connectors/nginx/src/ddebug.h` copied into the generated build tree when needed | The header only provides debug macros and sanity-check no-ops; it does not own hooks, filters, bodies, transactions, or libmodsecurity lifecycle | Removed after smoke validation |

## Phase 4 Removal Decision

One file was removed in phase 4. At that point:

- Apache `.in` templates are retained because `configure.ac` references them
  directly through `AC_CONFIG_FILES`.
- NGINX production source files were retained because `config` explicitly
  listed them as module sources or dependencies.
- NGINX `config` still listed `src/ddebug.h`, but the generated build copy
  received a repo-owned replacement when the selected source tree lacked it.
- License and attribution files were retained for provenance and redistribution
  clarity.

Any future deletion must be validated in an isolated copy under `$BUILD_ROOT`,
then followed by real-world Apache, NGINX, and combined smoke runs.

## Phase 5 No-Removal Decision

Phase 5 reviewed a second replacement candidate set and made no new removals.

| Candidate | Evidence | Decision |
| --- | --- | --- |
| Apache `id()` helper | No callers outside its declaration/definition, but removal would edit `msc_utils.c/.h`, which also owns `send_error_bucket()` declarations and Apache utility context | Defer as obsolete/reference-only until Apache adapter code is repo-owned |
| Apache `send_error_bucket()` | Called by `msc_filters.c`; creates Apache buckets and controls error response flow | Defer |
| NGINX `ngx_str_to_char()` | Used by config directives, location merge, and request metadata mapping | Defer |
| NGINX PCRE pool helpers | Tied to NGINX pool and rules/config loading lifecycle | Defer |
| NGINX response-header resolver helpers | Direct response header/filter path | Defer |
| NGINX log callback | Audit/log behavior remains evidence-sensitive | Defer |

No phase-5 candidate can be reduced without creating adapter-owned replacement
code in a production connector path. That is intentionally out of scope for
this review.

## Phase 8 Build-Input Reduction

The generated NGINX connector source tree reduces direct build dependence on the
former `connectors/nginx/upstream/` directory. At that point the retained
upstream tree remained a reference/provenance source, while the disposable
`$BUILD_ROOT` tree recorded the actual build-copy composition.

Apache receives the same manifest-only preparation. Its productive module build
still uses the sanitized upstream copy in phase 8.

## Phase 9 NGINX Source Migration

Phase 9 makes the generated NGINX build source adapter-owned by default:

- `connectors/nginx/config` materializes to root `config`;
- NGINX module sources and `ngx_http_modsecurity_common.h` materialize under
  `src/`;
- retained upstream `LICENSE`, `AUTHORS`, `CHANGES`, and `README.md` remain
  `upstream-derived` in the manifest;
- `MATERIALIZED_SOURCE.md` and `materialized-source.json` are
  `generated-overlay`;
- PR #377 patch provenance is recorded for body filter, common header, and
  module source entries.

This is a source ownership/build-input reduction, not a semantic promotion of
phase-4 response-body blocking. `RESPONSE_BODY` remains former expected-failure/mapped-only.

## Phase 10 Final NGINX Upstream Removal

Phase 10 removes the remaining NGINX upstream reference tree. The materialized
NGINX source is generated from adapter-owned `connectors/nginx/config`,
`connectors/nginx/src/`, and generated manifests only. Attribution is retained
in `licenses/nginx/`, `connectors/nginx/ORIGIN.md`, and
`connectors/nginx/SOURCE_MAP.json`.
