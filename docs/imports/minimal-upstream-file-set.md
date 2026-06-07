# Minimal Upstream File Set

Status: implemented

This document defines the current adapter-owned Apache and NGINX source sets
used by the monorepo smoke builds. The files remain connector-specific. Phase 9
migrated the NGINX module source into adapter-owned `connectors/nginx/src`;
Phase 10 removed the former NGINX `upstream/` reference tree. Phase 11 migrated
Apache source and Autotools/APXS inputs into `connectors/apache/src`, proved the
materialized Apache build, and removed the former Apache `upstream/` tree.
Phase 12 removed Apache attribution/history/documentation-only files from the
active source tree. No Apache hook, NGINX filter, body, transaction, or Common
runtime logic was merged across connectors.

## Apache Connector

Adapter-owned build source root: `connectors/apache/`

Required for build and module creation:

- `autogen.sh`
- `configure.ac`
- `Makefile.am`
- `build/apxs-wrapper.in`
- `build/ax_prog_apache.m4`
- `build/find_apxs.m4`
- `build/find_libmodsec.m4`
- `src/mod_security3.c`
- `src/mod_security3.h`
- `src/msc_config.c`
- `src/msc_config.h`
- `src/msc_filters.c`
- `src/msc_filters.h`
- `src/msc_utils.c`
- `src/msc_utils.h`

Build-only templates retained because `configure.ac` or the upstream test
layout references them:

- `t/conf/extra.conf.in`
- `tests/run-regression-tests.pl.in`
- `tests/regression/misc/40-secRemoteRules.t.in`
- `tests/regression/misc/50-ipmatchfromfile-external.t.in`
- `tests/regression/misc/60-pmfromfile-external.t.in`
- `tests/regression/server_root/conf/httpd.conf.in`

Provenance context retained outside the functional source tree:

- `connectors/apache/SOURCE_MAP.json`

Durable attribution outside the source tree:

- `licenses/apache/LICENSE`
- `licenses/apache/AUTHORS`
- `licenses/apache/CHANGES`
- `connectors/apache/ORIGIN.md`

Materialized build input:

- Monorepo-default Apache builds use
  `$BUILD_ROOT/apache-build/connector-src`.
- The materializer copies adapter-owned build files from `connectors/apache/`
  according to `connectors/apache/SOURCE_MAP.json`, preserves the generated
  Autotools layout, and writes `MATERIALIZED_SOURCE.md` plus
  `materialized-source.json`.
- The generated manifest is expected to list Apache source, build files, and
  templates as `adapter-owned`, with no Apache `upstream-derived` entries.

## NGINX Connector

There is no remaining NGINX `connectors/nginx/upstream/` tree. The former
upstream reference files were removed in Phase 10 after durable attribution was
confirmed in:

- `licenses/nginx/LICENSE`
- `licenses/nginx/AUTHORS`
- `licenses/nginx/CHANGES`
- `licenses/nginx/ORIGIN.md`
- `connectors/nginx/ORIGIN.md`
- `connectors/nginx/SOURCE_MAP.json`

Adapter-owned NGINX module build inputs:

- `connectors/nginx/config`
- `connectors/nginx/src/ngx_http_modsecurity_access.c`
- `connectors/nginx/src/ngx_http_modsecurity_body_filter.c`
- `connectors/nginx/src/ngx_http_modsecurity_common.h`
- `connectors/nginx/src/ngx_http_modsecurity_header_filter.c`
- `connectors/nginx/src/ngx_http_modsecurity_log.c`
- `connectors/nginx/src/ngx_http_modsecurity_module.c`
- `connectors/nginx/src/ddebug.h`
- `connectors/nginx/SOURCE_MAP.json`

PR #377 provenance:

- `connectors/nginx/src/ngx_http_modsecurity_body_filter.c`,
  `connectors/nginx/src/ngx_http_modsecurity_common.h`, and
  `connectors/nginx/src/ngx_http_modsecurity_module.c` include source changes
  from ModSecurity-nginx PR #377 commit
  `3d72b004ff27a78ea19c6b945870e2cae62a97ac`.
- Those changes are source-level phase-4 evidence only. `RESPONSE_BODY` remains
  former expected-failure/mapped-only and excluded from `verified_variables`.

Materialized build input:

- Monorepo-default NGINX builds use
  `$BUILD_ROOT/nginx-build/connector-src`.
- The materializer copies adapter-owned `connectors/nginx/config` and
  `connectors/nginx/src` files according to `connectors/nginx/SOURCE_MAP.json`
  and writes `MATERIALIZED_SOURCE.md` plus `materialized-source.json`.
- External NGINX source builds still use a sanitized external-source copy; if
  the selected external source tree lacks `src/ddebug.h`,
  `modules/ModSecurity-test-Framework/ci/prepare-nginx-build.sh` overlays the repo-owned header into the generated
  external build copy.

## Future Common Extraction Candidates

These are candidates only. They must not be moved until behavior is proven with
real-world connector smokes after extraction.

| Category | Apache source area | NGINX source area | Current decision |
| --- | --- | --- | --- |
| Debug compatibility | none | repo-owned `connectors/nginx/src/ddebug.h` | Replaced imported upstream debug helper |
| Ruleset loading | `src/msc_config.*` | `src/ngx_http_modsecurity_module.c` | Keep connector-specific |
| Transaction lifecycle | `src/mod_security3.c`, `src/msc_filters.*` | access/header/body/log sources | Keep connector-specific |
| Intervention handling | `src/mod_security3.c`, `src/msc_utils.*` | `src/ngx_http_modsecurity_module.c` | Keep connector-specific |
| Audit/logging | Apache log hook/filter code | `src/ngx_http_modsecurity_log.c` | Keep connector-specific |
| Request metadata mapping | Apache request/filter code | `src/ngx_http_modsecurity_access.c` | Keep connector-specific |
| Response metadata mapping | Apache output filter code | NGINX header/body filters | Keep connector-specific |
| Config model | Apache per-dir/server config | NGINX main/location config | Keep connector-specific |
| Error handling | Apache utility and hook paths | NGINX return/finalize paths | Keep connector-specific |

## Pruning Rule

Do not remove a file from an adapter-owned source tree unless all of the
following are true:

- It is not referenced by build metadata or source includes.
- It is not needed for license, attribution, or source-origin context.
- It is not a documented future common-extraction candidate.
- A disposable probe under `$BUILD_ROOT` proves that Apache, NGINX, and
  combined smokes still pass without it.

The phase-4 review found one safe replacement: the NGINX debug compatibility
header. Phase 9 migrated NGINX productive source into adapter-owned files.
Phase 10 removed the remaining NGINX upstream reference tree because no build
input depended on it and durable attribution stayed available elsewhere. Phase
11 migrated Apache productive source and build inputs into adapter-owned files,
proved a materialized Autotools/APXS build, and removed the former Apache
upstream tree. Phase 12 reduced the Apache adapter-owned source tree to
functional build/runtime inputs plus provenance metadata; attribution-only
files were moved to `licenses/apache/`.

## Phase 8 Shadow Build Source

Phase 8 does not remove additional upstream files. It changes the monorepo
default NGINX build input from a direct sanitized upstream copy to
`$BUILD_ROOT/nginx-build/connector-src`. That generated source tree contains
manifests identifying `adapter-owned`, `upstream-derived`, and
`generated-overlay` files.

Phase 11 supersedes the Apache phase-8 preparation: Apache now builds directly
from `$BUILD_ROOT/apache-build/connector-src`.

## Phase 9 NGINX Source Migration

Phase 9 moved the NGINX module `config` and all remaining module source files
from `connectors/nginx/upstream/` to `connectors/nginx/src/`, then removed the
upstream copies after a materialized-source NGINX smoke passed.

## Phase 10 NGINX Upstream Removal

Phase 10 removes the remaining `connectors/nginx/upstream/` attribution-only
tree. Monorepo-default NGINX builds now materialize from adapter-owned source
only. The generated manifest is expected to list NGINX `config` and module
sources as `adapter-owned`, with no NGINX `upstream-derived` entries.

## Phase 11 Apache Source Migration

Phase 11 moved Apache source, Autotools/APXS files, license/provenance files,
and required `.in` templates into `connectors/apache/src/`. The monorepo
default Apache source is now materialized to
`$BUILD_ROOT/apache-build/connector-src` and built from that generated tree.
The former `connectors/apache/upstream/` tree was removed after
`REFRESH=1 BUILD_ROOT=/src/ModSecurity-conector-apache-final-build make
smoke-apache` passed.

## Phase 12 Apache Source Cleanup

Phase 12 removed `AUTHORS`, `CHANGES`, `LICENSE`, and `README.md` from
`connectors/apache/src/`. The Autoconf source anchor was changed from `LICENSE`
to `src/mod_security3.c`, so attribution-only files are outside the build
source. Attribution remains in `licenses/apache/`, `connectors/apache/ORIGIN.md`,
and the `relocated_files` section of `connectors/apache/SOURCE_MAP.json`.

## Phase 13 Layout Simplification

Phase 13 keeps the materialized build layout stable while simplifying the
repository layout:

- Apache Autotools/APXS files are under `connectors/apache/`.
- Apache productive C files are directly under `connectors/apache/src/`.
- Apache retained Autotools templates are under `tests/cases/connector-specific/apache/` and
  materialize back to `t/` and `tests/`.
- Apache metadata and provenance are under `connectors/apache/metadata.*` and
  `connectors/apache/SOURCE_MAP.json`, not in `src/`.
- NGINX `config` is under `connectors/nginx/config` and materializes to root
  `config`.
- NGINX `src/` contains only productive module headers/sources plus `ddebug.h`.
- NGINX metadata and provenance are under `connectors/nginx/metadata.*` and
  `connectors/nginx/SOURCE_MAP.json`, not in `src/`.

## Phase 5 Review Result

Phase 5 reviewed a second possible reduction and made no additional upstream
changes. The remaining small helpers are not standalone debug/build shims:

- Apache `id()` appears unused, but removing it would edit the imported
  `msc_utils.c/.h` pair for no functional replacement.
- Apache `send_error_bucket()` owns Apache bucket/error response behavior.
- NGINX `ngx_str_to_char()` is shared by config parsing and request metadata
  mapping.
- NGINX PCRE pool helpers are part of rules/config lifecycle.
- NGINX response-header resolver helpers and log callback are active
  response/audit paths.

Those areas stay connector-specific until repo-owned adapter implementations
exist and before/after real-world smokes prove equivalence.
