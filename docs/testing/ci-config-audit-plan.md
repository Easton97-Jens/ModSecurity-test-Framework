# CI Config Audit And Cleanup Plan

**Language:** English | [Deutsch](ci-config-audit-plan.de.md)

Date: 2026-05-20

This document audits the current `ci/`, Makefile, docs, and GitHub workflow
configuration after the first central-config cleanup pass. It is a planning
document, not runtime evidence.

## Audit Scope

Audited paths:

- `ci/`
- `Makefile`
- `README.md`
- `docs/testing/`
- `.github/workflows/`

Primary search covered local workspace paths, system install assumptions,
GitHub source URLs, and build/source-root variables:

```sh
rg "<local-paths>|<system-paths>|github.com|MODSECURITY|BUILD_ROOT|SOURCE_ROOT" ci Makefile README.md docs/testing .github/workflows
```

## Current Positive State

- `modules/ModSecurity-test-Framework/ci/lib/common.sh` exists and is passive: it defines variables and functions only.
- `modules/ModSecurity-test-Framework/ci/lib/common.sh` now defines canonical/passive source aliases
  (`MODSECURITY_SOURCE_DIR`, `MODSECURITY_V3_SOURCE_DIR`,
  `MODSECURITY_V3_ROOT`) and optional installed-readiness hints/search lists.
- `make cloud-quick-check` is currently framework/generator/lint oriented and
  does not call `quick-all`, `installed-readiness`, or full connector smokes.
- `quick-framework-check.yml` is lightweight and automatic.
- `test-full-smoke-sequential.yml` is manual-only via `workflow_dispatch`.
- Local runtime targets still exist: `smoke-all`, `smoke-apache`,
  `smoke-nginx`, `quick-all`, and `quick-check`.
- No current audit finding requires changing `connectors/apache/src/` or
  `connectors/nginx/src/`.

## High-Impact Findings

### 1. Local Path Defaults Removed From Runtime Defaults

The follow-up patch removed runtime defaults that silently depended on local
workspace paths:

| Area | Current finding | Risk |
| --- | --- | --- |
| `modules/ModSecurity-test-Framework/ci/lib/common.sh` | `DEFAULT_BUILD_ROOT` now uses a portable local state/output path | `/src` remains usable only as explicit `BUILD_ROOT`. |
| `modules/ModSecurity-test-Framework/ci/lib/common.sh` | legacy v3 source-dir fallback variable removed | No parent-workspace fallback remains. |
| `Makefile` | `BUILD_ROOT` now defaults through local state/output settings | Make no longer implies `/src`. |
| `modules/ModSecurity-test-Framework/ci/provisioning/build-v3-under-src.sh` / `modules/ModSecurity-test-Framework/ci/runtime/run-v3-api-smoke.sh` / `modules/ModSecurity-test-Framework/ci/provisioning/check-v3-api-smoke-prereqs.sh` | `MODSECURITY_V3_DIR` defaults under `BUILD_ROOT` | v3 API helpers no longer default to `/src`. |
| `ci/provisioning/find-modsecurity-v3.sh` | Checks explicit aliases and `$SOURCE_ROOT/ModSecurity_V3` only | No sibling repo auto-detection remains. |
| Several scripts | Safety guards still protect root-level destructive targets | These are deletion-safety checks, not source fallbacks. |

Recommendation:

- Keep path policy centralized as future cleanup if more duplication appears.
- Require explicit `MODSECURITY_SOURCE_DIR`/`MODSECURITY_V3_SOURCE_DIR` or a
  `SOURCE_ROOT`-derived fetched checkout.
- Treat `/src` as an explicit user-provided build root only.
- Keep GitHub workflows explicit with `$RUNNER_TEMP`.

Risk:

- Medium. Removing local fallbacks changes convenience behavior, but it aligns
  the repo with explicit source/build configuration and avoids surprising local
  coupling.

### 2. Source Directory Naming Is Not Fully Centralized

`modules/ModSecurity-test-Framework/ci/lib/common.sh` now centralizes repo URLs/refs and the requested canonical source
aliases. Remaining follow-up work is to separate fetched source dirs from
adapter-owned source dirs more explicitly.

| Required variable | Current status |
| --- | --- |
| `MODSECURITY_SOURCE_DIR` | Defined as canonical alias |
| `MODSECURITY_V3_SOURCE_DIR` | Defined as compatibility alias |
| `MODSECURITY_V3_ROOT` | Defined as compatibility alias |
| `MODSECURITY_APACHE_SOURCE_DIR` | Defined centrally; repo-local by default |
| `MODSECURITY_NGINX_SOURCE_DIR` | Defined centrally; repo-local by default |

Recommendation:

- Add canonical `MODSECURITY_SOURCE_DIR="${MODSECURITY_SOURCE_DIR:-...}"`.
- Define `MODSECURITY_V3_SOURCE_DIR` and `MODSECURITY_V3_ROOT` as aliases to
  `MODSECURITY_SOURCE_DIR`, with existing env overrides winning.
- Keep adapter-owned repo-local source dirs explicit as separate variables:
  `APACHE_ADAPTER_SOURCE_DIR` and `NGINX_ADAPTER_SOURCE_DIR`.

Risk:

- Low to medium. Alias precedence must be explicit to avoid breaking old env
  names.

### 3. Repo URL Policy Is Explicit

Currently referenced external sources:

| Source | Location | Status |
| --- | --- | --- |
| `https://github.com/owasp-modsecurity/ModSecurity.git` | `modules/ModSecurity-test-Framework/ci/lib/common.sh`, workflow/docs | Core repo, expected |
| `https://github.com/owasp-modsecurity/ModSecurity-apache` | docs/import metadata only | Historical connector reference, not default fetch |
| `https://github.com/owasp-modsecurity/ModSecurity-nginx` | docs/import metadata only | Historical connector reference, not default fetch |
| `https://github.com/nginx/nginx` | `modules/ModSecurity-test-Framework/ci/lib/common.sh`, NGINX build helper, manual workflow | NGINX server source dependency |
| `https://downloads.apache.org/httpd/...` | `modules/ModSecurity-test-Framework/ci/lib/common.sh` | Apache/httpd server source dependency |
| `https://downloads.apache.org/apr/...` | `modules/ModSecurity-test-Framework/ci/lib/common.sh` | APR/APR-util server source dependency |
| `https://github.com/PCRE2Project/pcre2/...` | `modules/ModSecurity-test-Framework/ci/lib/common.sh` | Library source dependency |

Recommendation:

- Default fetch policy is ModSecurity core only.
- Apache/NGINX connector repositories require
  `ALLOW_EXTERNAL_CONNECTOR_REPOS=1` plus explicit URLs and source dirs.
- Source-built server dependencies remain configurable runtime-build inputs,
  not connector repos.

Risk:

- High if changed blindly. The full local source-built smoke currently depends
  on server/library source downloads unless source-built outputs or installed tools
  are supplied.

### 4. Fetch Reuse Does Not Validate Existing Git Checkouts

`modules/ModSecurity-test-Framework/ci/provisioning/fetch-smoke-sources.sh` currently:

- clones configured URL/ref into configured destination.
- reuses an existing `.git` directory without validating:
  - remote URL
  - current branch/ref/commit
  - dirty worktree
  - detached HEAD state

Recommendation:

- Add a `ci_validate_git_checkout "$dest" "$url" "$ref"` helper.
- If an existing checkout is dirty or remote URL/ref mismatches, return
  `BLOCKED` with a remediation message.
- Do not auto-reset, auto-fetch, or overwrite.
- Keep `REFRESH` behavior explicit if a future cleanup adds replacement logic.

Risk:

- Medium. Validation may block previously tolerated local states, but this is
  safer than silently using the wrong source.

### 5. Automatic Local Source Detection Is Explicit

`ci/provisioning/find-modsecurity-v3.sh` now searches:

1. `MODSECURITY_SOURCE_DIR`
2. `MODSECURITY_V3_SOURCE_DIR`
3. `MODSECURITY_V3_ROOT`
4. `$SOURCE_ROOT/ModSecurity_V3`

Recommendation:

- Update `doctor` and smoke preflight messages to say "run `make fetch-deps` or
  set `MODSECURITY_SOURCE_DIR`".

Risk:

- Medium. This removes convenient developer auto-detection, but prevents
  accidental use of unintended local sibling repos.

### 6. Installed Readiness Is Still Mixed Into Doctor Output

`modules/ModSecurity-test-Framework/ci/tools/doctor.sh` originally checked build tools, Python deps, source paths,
GitHub reachability, generated build outputs, and installed
Apache/NGINX/libmodsecurity readiness in one flow. It reports installed
components even for source-build validation.

`modules/ModSecurity-test-Framework/ci/runtime/smoke-installed.sh` is explicitly readiness-only, which is good, but the
installed detection logic still contains hardcoded system paths:

- `/lib/x86_64-linux-gnu`
- `/usr/lib/x86_64-linux-gnu`
- `/usr/local/lib`
- `/usr/lib64`
- `/usr/lib`
- `/usr/include`
- `/usr/local/include`
- `/opt/include`

Recommendation:

- Split doctor sections clearly:
  - `SOURCE-BUILD READINESS`
  - `OPTIONAL INSTALLED READINESS`
- Source-build readiness must not require system Apache, NGINX, or installed
  libmodsecurity.
- Move installed search path lists to `modules/ModSecurity-test-Framework/ci/lib/common.sh` as optional readiness
  defaults.
- Keep installed-readiness returning `BLOCKED` when incomplete, but document
  that this does not block source-built smoke.

Risk:

- Low to medium. Output semantics change, but runtime behavior should not.

### 7. Manual Full-Smoke Workflow Still Contains Runtime Defaults

`.github/workflows/test-full-smoke-sequential.yml` is manual-only, but still
contains:

- direct `MODSECURITY_V3_GIT_URL`
- direct `MODSECURITY_V3_GIT_REF`
- direct `NGINX_SOURCE_REPO_URL`
- `NGINX_RELEASE_TAG=latest`
- full `make smoke-*` commands

Recommendation:

- Keep manual-only status.
- Make workflow env use canonical names:
  `MODSECURITY_REPO_URL`, `MODSECURITY_GIT_REF`, and any future explicit
  `NGINX_SOURCE_REPO_URL`.
- Prefer pinned tags/refs for reproducibility over `latest`.
- Add a workflow comment that it is not required CI and may fetch/build server
  source dependencies.

Risk:

- Low if manual-only behavior stays unchanged.

### 8. Build Dependency Versions Are Not Centralized

`modules/ModSecurity-test-Framework/ci/lib/common.sh` now owns:

- `HTTPD_VERSION`
- `APR_VERSION`
- `APR_UTIL_VERSION`
- `PCRE2_VERSION`
- source URLs and optional checksums

- `NGINX_SOURCE_MODE`
- `NGINX_SOURCE_REPO_URL`
- `NGINX_RELEASE_TAG`
- `NGINX_SOURCE_GIT_REF`
- `NGINX_SHA256`

Recommendation:

- Keep empty checksum variables optional; local hashes are still recorded when
  no upstream checksum is configured.

Risk:

- Low for pure centralization; medium if checksum policy becomes strict.

## Safe Immediate Changes

These are safe to do in the next small patch. The first pass implemented these
items without changing runtime smoke semantics:

- Add missing passive aliases in `modules/ModSecurity-test-Framework/ci/lib/common.sh`:
  `MODSECURITY_SOURCE_DIR`, `MODSECURITY_V3_ROOT`, `APACHECTL_BIN`,
  `MODSECURITY_PKG_CONFIG`, `MODSECURITY_LIB_DIR`,
  `MODSECURITY_INCLUDE_DIR`.
- Move installed readiness search lists into passive variables/functions.
- Update docs to call `/src` an explicit example, not a requirement.
- Update `doctor` headings to separate source-build and optional installed
  readiness without changing exit policy.

Implemented status:

- `modules/ModSecurity-test-Framework/ci/lib/common.sh` now defines the missing source aliases and optional installed
  hints, plus centralized installed-readiness candidate/search-list variables.
- `modules/ModSecurity-test-Framework/ci/tools/doctor.sh` now reports `SOURCE-BUILD READINESS` and
  `OPTIONAL INSTALLED READINESS` separately.
- `modules/ModSecurity-test-Framework/ci/runtime/smoke-installed.sh` now consumes the centralized installed-readiness
  candidate/search-list variables.
- Documentation now clarifies that `/src` is a replaceable build-artifact
  location, installed-readiness is optional diagnostics, and `make smoke-all`
  remains the local authoritative runtime-evidence path.

## Former Expected-Failure YAML And CI Helper Follow-Up

The next conservative cleanup fixed malformed expected-failure YAML syntax only. The
repaired cases were previously unreadable by the matrix generator, which caused
them to appear as `unknown` reporting rows despite their source files declaring
a historical expected-failure status.

Syntax-only repairs:

- JSON request bodies with embedded quotes now use YAML-safe scalars.
- XML request bodies with embedded attribute quotes now use YAML-safe scalars.
- `origin.reason` values beginning with `@operator` are quoted.
- The outbound multiline audit-log probe body is indented as one YAML block
  scalar.

No test status, expected HTTP result, intervention expectation, runtime
verification claim, or RESPONSE_BODY classification was changed.

The `ci/` script audit found most helpers still referenced by Makefile targets,
runtime smoke scripts, docs, or compatibility wrappers. Two stale standalone
Python helpers for real-world summary schema checking and expected audit-log
fixture generation were removed. The lightweight common workflow now uses the
shared case runner CLI for those checks instead of calling deleted `ci/`
helpers.

Runtime/build/fetch/debug helpers were deliberately kept unless the reference
audit proved them dead. Full runtime validation remains local.

## Framework Extraction Follow-Up

The shared test/runtime/coverage layer is now owned by the sibling
`ModSecurity-test-Framework` checkout and consumed through configurable
`FRAMEWORK_ROOT` / `CONNECTOR_ROOT` paths.

Moved to the framework:

- common YAML cases and schema notes
- shared case runner and normalizers
- matrix, coverage, runtime-snapshot, and runtime-matrix generators
- generic source-build smoke orchestration helpers

Kept in this connector repository:

- Apache/NGINX connector source and harnesses
- adapter metadata and connector materialization checks
- `config/testing/import-status.json`
- connector-specific cases under `connectors/<connector>/tests/`
- generated connector reports under `docs/testing/generated`

Connector-local `ci/` entrypoints that overlap with framework-owned helpers are
compatibility wrappers only; they delegate to `$FRAMEWORK_ROOT`. No former expected-failure,
pending, connector-gap, or RESPONSE_BODY status was promoted by the extraction.

## Changes That Should Be Separate

These remain separate follow-ups:

- Add checkout remote/ref/dirty validation in `fetch-smoke-sources.sh`.
- Pin or remove `NGINX_RELEASE_TAG=latest`.

## Proposed Follow-Up Implementation Order

1. Add missing passive aliases and installed-readiness helper variables to
   `modules/ModSecurity-test-Framework/ci/lib/common.sh`.
2. Refactor `doctor` output into source-build and optional-installed sections;
   preserve existing BLOCKED/PASS honesty.
3. Add git checkout validation to `fetch-smoke-sources.sh`.
4. Pin or remove moving server-source refs where practical.
5. Update manual full-smoke workflow names/env further if needed and pin
   moving refs where practical.

## Non-Goals For This Audit Pass

- No `make smoke-all` execution.
- No Full-Smoke PASS claims.
- No RESPONSE_BODY promotion.
- No changes under `connectors/apache/src/` or `connectors/nginx/src/`.
- No runtime semantic changes without a separate reviewed patch.
