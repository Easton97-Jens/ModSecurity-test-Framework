# Framework variables and placeholders

**Language:** English | [Deutsch](variables.de.md)

This reference explains caller-configurable Framework values. A command still
needs a short local explanation beside its example; this page is the central
reference for repeated names.

## Quick reference

| Variable | Area | Required | Default | Format | Short description |
|---|---|---:|---|---|---|
| [`FRAMEWORK_ROOT`](#framework_root) | paths | No | Framework checkout | absolute directory | Framework repository root |
| [`CONNECTOR_ROOT`](#connector_root) | paths | Target-dependent | current directory | absolute directory | Connector repository root |
| [`BUILD_ROOT`](#build_root-source_root-tmp_root-and-log_root) | build | No | state-local directory | absolute writable directory | Generated build artifacts |
| [`SOURCE_ROOT`](#build_root-source_root-tmp_root-and-log_root) | provisioning | No | state-local directory | absolute directory | Source acquisition location |
| [`TMP_ROOT`](#build_root-source_root-tmp_root-and-log_root) | runtime | No | below `BUILD_ROOT` | absolute directory | Temporary runtime files |
| [`LOG_ROOT`](#build_root-source_root-tmp_root-and-log_root) | logging | No | below `BUILD_ROOT` | absolute directory | Build and runtime logs |
| [`EVIDENCE_ROOT`](#evidence_root) | evidence | No | below `BUILD_ROOT` | absolute directory | No-CRS evidence runs |
| [`NO_CRS_RUN_ID`](#no_crs_run_id) | No-CRS | Canonical runs | `local` | filesystem-safe token | Evidence-run identity |
| [`CONNECTOR`](#connector-capabilities_file-evidence_stage-and-no_crs_artifact_profile) | No-CRS | Connector targets | none | connector key | Capability-manifest selector |
| [`PYTHON`](#tooling-status-values-and-sensitive-data) | tooling | No | `.venv/bin/python` or `python3` | executable path | Interpreter used by Make |
| [`PROTOCOL_URL`](#protocol_url) | protocol | `protocol-client` | none | `http(s)://` URL | Explicit client target |
| `<fresh-source-root>` | five-connector CRS fixture | `verify-fixture` and `validate` | none | absolute directory | Fresh CRS source root containing `coreruleset/` |
| `<private-root>` | five-connector evidence | `validate` and `aggregate` | none | private absolute directory | Externally produced evidence and validator outputs |

## Repository, build, and runtime paths

### `FRAMEWORK_ROOT`

| Property | Meaning |
|---|---|
| Purpose | Locates Framework tests, CI tools, catalog files, and Framework reports. |
| Format | Absolute path to this repository checkout. |
| Required | Optional for Make; required when a nested CI script is launched from another directory. |
| Default | The Framework checkout; CI path bootstrap discovers it from the entrypoint. |
| Set by | Makefile, caller, or CI path bootstrap. |
| Scope | One command and child processes. |
| Example | `/work/ModSecurity-test-Framework` |
| Effect | Changes where Framework-owned source and docs are read. |
| Security | Do not execute a checkout you do not trust. |

### `CONNECTOR_ROOT`

| Property | Meaning |
|---|---|
| Purpose | Locates connector source, capability manifests, and connector reports. |
| Format | Absolute connector-repository root. |
| Required | Required when a target reads connector-owned files; optional for Framework-only catalog checks. |
| Default | Current directory for most targets; Framework root for Framework report refreshes. |
| Set by | Caller, Makefile, or runtime script. |
| Scope | One connector command or report generation run. |
| Example | `/work/ModSecurity-conector` |
| Effect | Selects `connectors/<connector>/` and `reports/testing/`. |
| Security | Must be trusted; writers validate output paths. |

### `BUILD_ROOT`, `SOURCE_ROOT`, `TMP_ROOT`, and `LOG_ROOT`

| Property | `BUILD_ROOT` | `SOURCE_ROOT` | `TMP_ROOT` | `LOG_ROOT` |
|---|---|---|---|---|
| Purpose | Build output | Sources | Temporary files | Diagnostics |
| Format | absolute writable directory | absolute directory | absolute writable directory | absolute writable directory |
| Required | optional | optional | optional | optional |
| Repository default | state-local | state-local | `BUILD_ROOT/tmp` | `BUILD_ROOT/logs` |
| Set by | Makefile, `ci/lib/common.sh`, or caller | same | same | same |
| Example | `<temporary-work-root>/build` | `<temporary-work-root>/src` | `<temporary-work-root>/tmp` | `<temporary-work-root>/logs` |
| Effect | Keeps generated output outside Git | selects source location | isolates transient files | selects log location |
| Security | Do not use a checkout or unisolated shared path | verify provenance | review before sharing | review before sharing |

The examples are temporary runtime paths, not repository-relative paths or
required host defaults.

## Evidence and No-CRS

### Five-connector With-CRS / No-MRTS command placeholders

`ci/checks/catalog/five_connectors_with_crs_no_mrts.py` uses explicit,
validated command arguments. Its closed profile is
`five-connectors-with-crs-no-mrts` for `apache`, `haproxy`, `envoy`,
`traefik`, and `lighttpd`; `nginx` is deliberately rejected for this profile
only.

| Placeholder | Required by | Meaning and constraint |
|---|---|---|
| `<fresh-source-root>` | `verify-fixture`, `validate`, `aggregate` | Absolute source root with a fresh `coreruleset/` checkout. The validator checks the pinned CRS rule file; it does not fetch or reuse an uncontrolled source. |
| `<private-root>` | `validate`, `aggregate` | Absolute, non-symlink, group/world-inaccessible directory outside the Framework checkout. It contains host-provided input and receives new result artifacts; existing result paths are refused. |
| `<fixed-connector>` | `validate` | Exactly one of `apache`, `haproxy`, `envoy`, `traefik`, or `lighttpd`. |
| `<id>` | `validate`, `aggregate` | Safe correlation token shared only by the five evidence bundles being validated. Do not use secrets, personal data, or customer identifiers. |

The validator derives the Framework commit from its clean checkout and rejects
a caller-supplied override. These arguments validate evidence only. They do
not provision CRS, start a connector, run MRTS, or establish a
connector-runtime PASS.

| Make variable | Used by | Meaning and constraint |
|---|---|---|
| `FIVE_CONNECTORS_WITH_CRS_NO_MRTS_EVIDENCE_ROOT` | `five-connectors-with-crs-no-mrts-validate`, `five-connectors-with-crs-no-mrts-aggregate` | Private evidence root passed to the fixed validator; it must meet the same path and permission requirements as `<private-root>`. |
| `FIVE_CONNECTORS_WITH_CRS_NO_MRTS_RUN_ID` | `five-connectors-with-crs-no-mrts-validate`, `five-connectors-with-crs-no-mrts-aggregate` | Required safe run ID. |
| `FIVE_CONNECTORS_WITH_CRS_NO_MRTS_CONNECTOR` | `five-connectors-with-crs-no-mrts-validate` | Required closed-set member; the Python CLI rejects every other connector. |

### `EVIDENCE_ROOT`

| Property | Meaning |
|---|---|
| Purpose | Root for canonical No-CRS evidence directories. |
| Format | Absolute writable directory. |
| Required | Optional locally; needed for a published canonical run. |
| Default | `BUILD_ROOT/no-crs-evidence`. |
| Set by | Makefile or caller. |
| Scope | One or more evidence runs. |
| Example | `<temporary-work-root>/evidence` |
| Effect | Parents `<connector>/<run-id>/` artifacts. |
| Security | Do not put secrets, user names, or ticket text in the path. |

### `NO_CRS_RUN_ID`

| Property | Meaning |
|---|---|
| Purpose | Identifies one evidence run. |
| Format | Short filesystem-safe token without `/` or `..`. |
| Required | Yes for canonical evidence; optional locally. |
| Default | `local`. |
| Set by | Caller, workflow, or orchestrator. |
| Scope | One complete connector or aggregate run. |
| Example | `six-connectors-core-20260712T164725Z` |
| Effect | Names evidence, plan, summary, and log subdirectories. |
| Security | Never use credentials, personal data, or customer IDs. |

### `CONNECTOR`, `CAPABILITIES_FILE`, `EVIDENCE_STAGE`, and `NO_CRS_ARTIFACT_PROFILE`

| Variable | Purpose | Required | Default | Example |
|---|---|---:|---|---|
| `CONNECTOR` | Selects the connector catalog context. | Yes for connector targets | none | `nginx` |
| `CAPABILITIES_FILE` | Manifest used by selection and validation. | No | `CONNECTOR_ROOT/connectors/CONNECTOR/capabilities.json` | `/work/ModSecurity-conector/connectors/nginx/capabilities.json` |
| `EVIDENCE_STAGE` | Existing stage to record. | No | `no_crs_baseline` | `minimal_runtime_smoke` |
| `NO_CRS_ARTIFACT_PROFILE` | Existing artifact layout profile. | No | `generic` | `full_lifecycle` |

The caller or Makefile sets these values for one plan/init/finalize sequence.
They change selection and validation paths, never connector runtime semantics.
Use catalog-supported values only. Related orchestration inputs are
`NO_CRS_RUN_DIR`, `PLAN_FILE`, `NO_CRS_STAGE_RC`, `NO_CRS_STAGE_REASON`,
`NO_CRS_FINALIZE_ARGS`, `NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR`, and
`NO_CRS_SUMMARY_ROOT`; their defaults are below `BUILD_ROOT` or `EVIDENCE_ROOT`.
`NO_CRS_STAGE_REASON` must not contain secrets or personal data.

`NO_CRS_FINALIZE_ARGS` accepts additional `finalize` options. Its value is
parsed as POSIX shell-style quoting into individual arguments, so quote an
option value containing spaces. It is passed to the finalizer as argument data,
not evaluated as Make or shell code; control operators such as `;` remain
literal arguments, as does Make function syntax such as `$(...)`.

## Protocol, cache, and provisioning

### `PROTOCOL_URL`

| Property | Meaning |
|---|---|
| Purpose | Explicit endpoint for `make protocol-client`. |
| Format | `http://` or `https://` URL. |
| Required | Yes for `make protocol-client`. |
| Default | No default. |
| Set by | Caller or workflow. |
| Scope | One protocol-client invocation. |
| Example | `https://127.0.0.1:8443/phase4` |
| Effect | Selects the target recorded in payload-free client evidence. |
| Security | Test URLs can reveal internal host names. |

`PROTOCOL_PROFILE` defaults to `http1`; `PROTOCOL_ARTIFACT_DIR` is below
`BUILD_ROOT`; `PROTOCOL_STRICT` and `PROTOCOL_INSECURE` default to `0`.
`PROTOCOL_FOLLOWUP_URL` is required only for strict evidence. Optional binding
fields are `PROTOCOL_CONNECTOR`, `PROTOCOL_INTEGRATION_MODE`,
`PROTOCOL_RUN_ID`, `PROTOCOL_TRANSACTION_ID`, `PROTOCOL_TRANSPORT_CASE_ID`,
`PROTOCOL_RULE_ID`, `PROTOCOL_PHASE`, `PROTOCOL_STREAM_ID`,
`PROTOCOL_UPSTREAM_PROTOCOL`, `PROTOCOL_QUIC_UDP_OBSERVED`, and
`PROTOCOL_OBSERVATION_SIDECAR`. `PROTOCOL_CACERT` is a certificate path; a
private key is secret and must never be passed or recorded here.

The stable public targets keep their hyphenated names while using maintained
underscore-named tools: `make protocol-client` runs
`ci/checks/protocol/protocol_client.py`, `make check-protocol-evidence` runs
`ci/checks/protocol/check_protocol_evidence.py`, and
`make check-transport-hardening-evidence` runs
`ci/checks/evidence/check_transport_hardening_evidence.py`.

`MRTS_ROOT`, `MRTS_BUILD_ROOT`, `MRTS_DEFINITIONS`, `MRTS_RULES_OUT`,
`MRTS_FTW_OUT`, `MRTS_LOAD_FILE`, and `MRTS_CASE_ROOT` select existing MRTS
inputs or generated paths. `MODSECURITY_MRTS_VARIANT` accepts `no-mrts` or
`with-mrts`; `MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1` enables optional demo
content only after collision checks.

`CRS_APPROVED_REPO_URL` and `CRS_APPROVED_COMMIT` are central literal
provenance values in `ci/lib/common.sh`, currently
`https://github.com/coreruleset/coreruleset.git` and
`55b09f5acfd16413e7b31041100711ceb7adc89c`. They are not caller inputs.
`CRS_GIT_REF=v4.28.0` is the fixed release-tag leg of that reviewed tuple.
`fetch-crs.sh` rejects a differing `CRS_REPO_URL` or `CRS_GIT_REF` before Git
runs, fetches only the exact central tag ref, and requires its peeled object to
equal `CRS_APPROVED_COMMIT`; it never accepts a caller-selected ref. Environment
attempts to replace either approved provenance literal are overwritten by the
central definition.

`CRS_SOURCE_DIR` must be an absent path below the permitted external
`SOURCE_ROOT`; an existing directory or link is rejected rather than reused.
The fetch path initializes a fresh repository, sets and reads back the exact
HTTPS origin, fetches the approved full commit without automatic tags or
recursive submodules, then fetches only the exact reviewed tag ref and compares
its peeled object, `FETCH_HEAD^{commit}`, the resolved commit object, and final
`HEAD^{commit}` with that same identity. An absent `.gitmodules`
path is accepted. The one present root `.gitmodules` path is accepted only as
the regular, non-symlinked, zero-byte Git empty blob
`e69de29bb2d1d6434b8b29ae775ad8c2e48c5391` in the approved tree, checkout
index, and worktree. The approved tree and checkout index must contain no
Gitlink, and no nested manifest, local `submodule.*` configuration, or
`.git/modules` registry may exist. Every other manifest or submodule state is
rejected before use; no recursive submodule initialization occurs. The same
checkout verifier runs in `prepare-crs.sh` immediately before it reads source
templates, rules, or plugins or writes runtime files, so a replacement after
fetch is rejected at the source-consumption boundary.
`CRS_RUNTIME_DIR` and `MODSECURITY_RULE_PREAMBLE_FILE` remain runtime-path
inputs. Do not duplicate CRS pins in workflows. `CACHE_ROOT`,
`VERIFIED_COMPONENT_CACHE`, and `CONNECTOR_COMPONENT_CACHE` are cache paths
and require provenance checks.

`MODSECURITY_V3_APPROVED_REPO_URL` and `MODSECURITY_V3_APPROVED_COMMIT` are
literal ModSecurity v3 provenance values in `ci/lib/common.sh`, currently
`https://github.com/owasp-modsecurity/ModSecurity.git` and
`0fb4aff98b4980cf6426697d5605c424e3d5bb60`.
`MODSECURITY_V3_RELEASE_TAG=v3.0.15` is release metadata only. The legacy
`MODSECURITY_REPO_URL`, `MODSECURITY_V3_GIT_URL`, `MODSECURITY_GIT_REF`, and
`MODSECURITY_V3_GIT_REF` aliases normalize to those reviewed values when empty
or unset; a non-empty differing value is rejected before Git use and never
selects an object. The V3 fetch route initializes a fresh repository, verifies its literal origin,
fetches the full commit without tags or automatic recursive submodules, and
compares the fetched, resolved, and checked-out commit identities. It then
explicitly initializes only the static approved recursive topology. A V3 build
input must have that root identity and the exact eight-child `(path, origin,
commit)` graph declared by the `ci_modsecurity_v3_*_gitlinks` helpers in
`ci/lib/common.sh`; every checkout must be non-symlinked, contained, detached,
clean, and have exactly one approved `origin`. `.gitmodules` and Gitlinks are
accepted only as that exact static graph; missing, extra, or mismatched
topology is rejected. The only fresh-provisioning entry point is
`ci_provision_approved_modsecurity_v3_checkout`; it requires an absent
destination directly below an existing canonical non-symlinked parent, creates
that destination privately, and does not reuse an existing V3 source. Its
provenance operations use the verified `/usr/bin/git` rather than a caller's
`PATH`, run post-init commands from the new root's canonical physical
directory with an explicit worktree while keeping `GIT_DIR` and `GIT_WORK_TREE`
unset for Git's recursive helper, and clear local redirect, attributes,
sparse-checkout, and custom recursive-update
configuration before submodule processing.

## Tooling, status values, and sensitive data

`PYTHON` defaults to `.venv/bin/python` when present, otherwise `python3`.
`PYTHONDONTWRITEBYTECODE=1` is the repository default. `REFRESH`,
`SMOKE_CASES`, `CASE_SCOPE`, `FORCE_ALL_CASES`, `EXTRA_CASE_ROOTS`,
`RESULTS_DIR`, and the `VERIFIED_*` roots constrain existing runs; they do not
add capabilities or cases. Connector-family overrides (`APXS_*`, `NGINX_*`,
`HAPROXY_*`, `ENVOY_*`, `TRAEFIK_*`, and `LIGHTTPD_*`) are optional overrides
of pinned defaults in `ci/lib/common.sh`.

`make lint` is static validation, not runtime proof. `make check-no-crs-catalog`
validates catalog structure. `make protocol-client` needs `PROTOCOL_URL`.
Exit `0` means only that the invoked command completed its checks; it does not
mean every catalog case is PASS. `1` is a general error, `2` an invalid
argument or contract error, and `77` an explicitly unavailable prerequisite.
Case statuses are `PASS`, `FAIL`, `BLOCKED`, `NOT EXECUTED`, `NOT APPLICABLE`,
and `UNSUPPORTED`; see the [glossary](glossary.md).

Never commit, log, or copy private keys, tokens, cookies, authorization
headers, passwords, API keys, or client secrets into canonical evidence. Use
`<secret-from-secure-store>` in a non-executable example instead of a value.

## Additional documented inputs and placeholders

The values below appear in focused build, import, testing, or historical
compatibility guides. They are optional overrides unless their named target says
otherwise. Their source of truth is the target or `ci/lib/common.sh`; an empty
or unavailable value must result in a clear prerequisite error rather than an
assumed PASS. Build paths are absolute runtime paths and should remain outside
the Git worktree. Version, URL, and checksum overrides require provenance
review before use.

| Names | Area and format | Default / setter | Example and safety note |
|---|---|---|---|
| `ALLOW_EXTERNAL_CONNECTOR_REPOS` | source acquisition boolean | `0`; caller or CI | `1` opts in to external source fetches; review the repository first. |
| `BUILD_HTTPD_FROM_SOURCE`, `BUILD_NGINX_FROM_SOURCE`, `BUILD_PCRE2_FROM_SOURCE`, `XDG_STATE_HOME` | build boolean or state-home path | target default or host state home; caller | `1` enables the named source build; `XDG_STATE_HOME=<temporary-work-root>/state` selects a state-home outside Git. |
| `APACHE_BIN`, `APACHECTL_BIN`, `APXS_BIN`, `HTTPD_PREFIX`, `HTTPD_VERSION`, `APR_VERSION` | Apache executable/path or version override | central pin or host discovery | `/opt/httpd/bin/httpd`; do not treat a host installation as portable evidence. |
| `APR_UTIL_PINNED_VERSION`, `APR_UTIL_PINNED_SOURCE_URL`, `APR_UTIL_PINNED_SHA256`, `APR_UTIL_PINNED_SHA256_URL`, `APR_UTIL_VERSION`, `APR_UTIL_SOURCE_URL`, `APR_UTIL_SHA256`, `APR_UTIL_SHA256_URL` | atomic APR-util provider, asset, and SHA-256 tuple | version plus literal digest; URLs are derived | The updater selects the newest stable compatible release from `downloads.apache.org/apr/` and accepts exactly one matching entry from `<asset>.sha256`. It changes version and digest together; runtime aliases and both URLs remain derived. Host/path/override validation still blocks before network or extraction. |
| `NGINX_BIN`, `NGINX_GITHUB_REPO`, `NGINX_RELEASE_TAG`, `NGINX_SOURCE_GIT_REF`, `NGINX_RELEASE_ASSET_NAME`, `NGINX_SOURCE_MODE`, `NGINX_SOURCE_REPO_URL`, `NGINX_SHA256` | NGINX executable, compatibility GitHub URL alias, fixed release tag/ref, release-asset name, source mode, or SHA-256 digest input | reviewed fixed source tuple; see [NGINX fixed-release provenance](#nginx-fixed-release-provenance) | NGINX accepts only the reviewed `github-release` provenance path. A floating `latest` tag or ref is rejected; it is not a supported compatibility mode. |
| `PCRE2_VERSION`, `PCRE_CONFIG` | dependency version or executable | central pin or host discovery | `PCRE_CONFIG=/usr/bin/pcre2-config`; a host path is only an example. |
| `PCRE2_VERSION`, `PCRE2_SOURCE_URL`, `PCRE2_SHA256`, `PCRE2_SHA256_URL`, `PCRE_CONFIG` | dependency version, HTTPS source URL, 64-hex SHA-256, version-tooling metadata, or executable | central pin or host discovery | `PCRE2_SHA256=<64-hex>` must be non-empty, syntactically valid, and exactly match the archive before extraction. Empty, whitespace-only, malformed, or mismatching values block before `tar`; `PCRE2_SHA256_URL` is not a fallback. |
| `MODSECURITY_APACHE_SOURCE_DIR`, `MODSECURITY_NGINX_SOURCE_DIR`, `MODSECURITY_SOURCE_DIR`, `MODSECURITY_V3_SOURCE_DIR`, `MODSECURITY_V3_DIR`, `MODSECURITY_V3_ROOT` | absolute source/build directory | below `SOURCE_ROOT` or `BUILD_ROOT` | `<temporary-work-root>/src/libmodsecurity`; V3 source must be a reviewed standalone checkout, never an untrusted checkout. |
| `MODSECURITY_GIT_REF`, `MODSECURITY_V3_GIT_REF`, `LIBMODSECURITY_VERSION`, `MODSECURITY_INCLUDE_DIR`, `MODSECURITY_LIB_DIR`, `MODSECURITY_INC`, `MODSECURITY_LIB`, `MODSECURITY_PKG_CONFIG` | release metadata, version, include/lib/pkg-config override | central pin or discovery | `MODSECURITY_GIT_REF=MODSECURITY_V3_GIT_REF=v3.0.15`; the full reviewed commit, not either alias, selects V3 source. |
| `MODSECURITY_TEST_VARIANT` | test variant enum | `no-crs` or target-selected | `with-crs` loads CRS before local rules; it does not change catalog semantics. |
| `MRTS_NATIVE_ROOT` | absolute MRTS source path | derived from `MRTS_ROOT` | `<temporary-work-root>/src/MRTS`; generated output remains under `MRTS_BUILD_ROOT`. |
| `FORCE_ALL_CASES`, `REFRESH`, `RESPONSE_BODY_PROBE_REPEAT` | test/report boolean or positive count | target default | `FORCE_ALL_CASES=1`; does not promote evidence automatically. |
| `RESULTS_DIR`, `LOG_DIR`, `RUN_DIR`, `STDOUT_LOG`, `STDERR_LOG`, `RAW_RESULT` | generated runtime/evidence paths | below `BUILD_ROOT` or the run directory | `<temporary-work-root>/build/results`; logs may contain sensitive diagnostics. |
| `CANONICAL_EVENTS`, `HOST_RC`, `HOST_VERSION`, `NAME`, `NO_CRS_BASELINE`, `RUN_ID` | evidence metadata value or `--source-log NAME=PATH` label | evidence tool or caller | `RUN_ID=six-connectors-core-20260712T164725Z`; do not place secrets in metadata. |
| `GITHUB_WORKSPACE`, `RUNNER_TEMP` | CI-provided absolute paths | GitHub Actions runner | set by the runner; never assume them on a local host. |
| `HOME`, `PWD`, `TMPDIR` | host shell paths | host shell | inherited from the shell; use an explicit Framework root for reproducibility. |
| `TARGET` | Make target name | supplied by `make` or the caller | `TARGET=linux-glibc`; allowed values depend on the invoked upstream build. |
| `USER_TOKEN` | sensitive authentication value | no repository default | `<secret-from-secure-store>`; never commit, log, or pass it in a visible process argument. |

### NGINX fixed-release provenance

NGINX source provisioning is a fixed, reviewed release path rather than a
rolling channel. When a caller leaves the tuple unset, the static reviewed
default is used. An explicitly supplied empty value is invalid and fails
closed; `NGINX_SOURCE_GIT_REF` may be derived only from the explicit reviewed
`NGINX_RELEASE_TAG`.

| Tuple field | Required reviewed value |
|---|---|
| `NGINX_SOURCE_MODE` | `github-release` |
| `NGINX_SOURCE_REPO_URL` | `https://github.com/nginx/nginx` |
| `NGINX_RELEASE_TAG` | `release-1.31.3` |
| `NGINX_SOURCE_GIT_REF` | `release-1.31.3` |
| `NGINX_RELEASE_ASSET_NAME` | `nginx-1.31.3.tar.gz` |
| `NGINX_SHA256` | `a7657c50811c2d92d9895395e8b873ef60398142c4db21eb647811c38f6dd525` |

`NGINX_GITHUB_REPO` is a compatibility alias only; it cannot select an origin
other than `https://github.com/nginx/nginx`. The resulting archive endpoint is
`https://github.com/nginx/nginx/releases/download/release-1.31.3/nginx-1.31.3.tar.gz`.

For NGINX, `latest` is prohibited as both `NGINX_RELEASE_TAG` and
`NGINX_SOURCE_GIT_REF`. Those values, a missing tag/ref/asset/digest, an
invalid digest, a noncanonical source repository or source mode, and a
tag/ref/asset mismatch are rejected before cache selection, a network request,
download, or extraction. The NGINX provenance check resolves only the
configured tag through `/releases/tags/<tag>`; it never uses the NGINX
`/releases/latest` endpoint. A newer NGINX release requires a separate atomic
review of the full tuple.

Cache reuse is bound to a non-symlinked manifest and a key over the full
`(source repository, source mode, release tag, source ref, release asset name,
expected SHA-256)` tuple. A cache entry with a missing, mismatched, or legacy
`latest` identity cannot be reused. The selected archive must match the
non-empty, 64-hex `NGINX_SHA256` value before it is staged or extracted, and
the staged copy is verified again. These source-provenance checks do not claim
a connector or production-runtime result.

| Placeholder | What to replace | Allowed values and example |
|---|---|---|
| `<connector>` | Connector catalog key | `apache`, `nginx`, `haproxy`, `envoy`, `traefik`, or `lighttpd`; for example `nginx`. |
| `<run-id>` | Filesystem-safe evidence-run token | no `/` or `..`; for example `six-connectors-core-20260712T164725Z`. |
| `<workspace>` | Portable checkout parent or CI workspace | an absolute workspace path, for example `/work/modsecurity`. |
| `<temporary-work-root>` | Portable alias for a generator's temporary work directory | an absolute, writable directory outside the Git worktree, for example a caller-provided `TMP_ROOT`; it is a presentation alias, not a literal path to copy into a command. |
| `<case>` and `<name>` | Catalog case identifier or metadata name | use an existing YAML `name`, for example `request-headers-basic`. |
| `<TAG>` | Existing upstream tag | use a reviewed upstream tag, for example `v1.27.0`. |
| `<local-paths>`, `<system-paths>`, `<local-build-root>`, and `<Location>` | Documentation placeholders for lists or a configuration section | replace with the local paths or section actually used; for example `<temporary-work-root>/build` or `<Location /protected>`. |
| `<secret-from-secure-store>` | Non-executable secret placeholder | retrieve it through the approved secret store; it must never become a committed literal. |

### Upstream version maintenance

`ci/tools/check-common-versions.py --list-components` lists canonical names; repeat
`--component NAME` to run a bounded subset. Apache/httpd/APR/APR-util use official
per-asset `.sha256` files; HAProxy uses its official series directory; Envoy,
Traefik, PCRE2, NGINX, and OpenSSL use exact GitHub release assets with an
upstream asset digest or exact official checksum manifest; lighttpd uses its
official `latest.txt` and `.sha256sum`. Compatibility-series restrictions are
reported as update policies rather than being implicit. CRS and ModSecurity v3
remain manual: their release tag must be reviewed together with the peeled,
immutable Git commit. Connector-local sources, prompt-only go-ftw/Albedo/Expat
metadata, and `DEFAULT_BRANCH` are explicitly not applicable.
