# Change record

**Language:** English | [Deutsch](20261120-01-modsecurity-bundled-pcre2.de.md)

**Pre-publication validation snapshot.** This record captures the implemented provisioning change and the observed local checks and builds. No hosted CI success, merge or Parent pin change is claimed.

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261120-01-modsecurity-bundled-pcre2 |
| UTC date | 2026-11-20 |
| Framework base revision | `95f228936efe17fda24f21323ad87cd698940b48` |
| Issue or pull request | Draft pull request from task branch `fix/modsecurity-bundled-pcre2-20261119`. |

## Motivation and problem statement

The shared libModSecurity prefix (`v3.0.17`) was configured without `--with-pcre2`, compiled against the distribution PCRE2 headers (10.46 on the local Ubuntu test host) and published without `DT_RUNPATH`. The NGINX, HAProxy and lighttpd harnesses put only `MODSECURITY_LIB_DIR` on the library path, so every libModSecurity process there loaded the distribution PCRE2 instead of the central pin `PCRE2_VERSION=10.49` from `ci/lib/common.sh`. Only Apache loaded the pinned PCRE2, through its own internal PCRE2 prefix. PCRE2 10.47 and later export versioned symbols (`PCRE2_10.47`); a binary built against the pin cannot be satisfied by an older distribution library, which the loader reports as `no version information available` and the linker as undefined `pcre2_*@PCRE2_10.47` references.

The host binaries were not bound either. NGINX was compiled against the distribution PCRE2 headers without a run path. `httpd` carried absolute run paths into its temporary staging tree, which no longer exists after publication. `mod_security3.so` had no run path at all. Outside a harness library path they loaded the distribution PCRE2, APR and APR-util, and the Apache module loaded the distribution libModSecurity 3.0.14.

## Affected components and security boundaries

The change is limited to the shared libModSecurity cache entry produced by `prepare-runtime-components.py` and to the NGINX and Apache host builds in `ci/provisioning/prepare-nginx-build.sh` and `ci/provisioning/prepare-apache-build.sh`. Host harnesses, adapters, Parent connectors and MRTS are unchanged. The PCRE2 archive is obtained through the existing digest-verifying archive cache with the required literal `PCRE2_SHA256` pin and the same `PCRE2_SOURCE_URL` the Apache build already uses; no new network endpoint is introduced. Extraction uses the `tarfile` `data` filter and accepts exactly one top-level directory.

## Acceptance criteria

libModSecurity is compiled and linked against the pinned PCRE2. The published prefix contains the pinned `libpcre2-8.so.0` next to `libmodsecurity.so.3`, which has `NEEDED libpcre2-8.so.0`, `DT_RUNPATH` exactly `$ORIGIN` and no legacy `RPATH`; any other result fails the build and nothing is published. The cache identity binds the PCRE2 tuple and output layout version 2, so no layout-1 entry is reused. The bundled ModSecurity tools also link against the pin. A missing or mismatching archive, an unreadable archive, an unexecutable build tool and a failing `readelf` inspection all fail closed with a recorded reason. NGINX links the bundled PCRE2 and carries the published libModSecurity `lib/` as `DT_RUNPATH`. `httpd` carries `$ORIGIN/../lib` for APR and an `$ORIGIN`-relative entry for its source-built PCRE2. `mod_security3.so` carries the published libModSecurity `lib/`. Each host build verifies its entries with `readelf` and fails otherwise.

## Alternatives considered

Adding the PCRE2 prefix to each harness library path would touch five adapters and still miss consumers without a harness, such as CGo binaries. A separate shared PCRE2 cache component would change the cache schema and every connector key. An absolute `DT_RUNPATH` to the final prefix is circular, because the final path contains the cache key derived from the build flags. Post-processing with `patchelf` adds a tool that the hosts do not provide. Bundling PCRE2 into the libModSecurity prefix with an `$ORIGIN` run path covers every consumer that loads the prefix.

## Implementation decision

`build_modsecurity_staging_entry` first installs the pinned PCRE2 into the staging prefix (`./configure --prefix=<staging>`, the same configuration as the Apache source build) and removes its libtool archives, so libtool cannot hardcode the temporary staging path. ModSecurity is then configured with `--with-pcre2=<staging>`. The build environment sets `LD_RUN_PATH=$ORIGIN`, which the linker uses unexpanded when no explicit `-rpath` is given. It also puts `-L<staging>/lib` first, so that dependency flags such as `-L/usr/lib/<triplet>` cannot make the bundled tools, examples and test programs resolve the distribution PCRE2. Automake places per-target `*_LDFLAGS` before `$(LDFLAGS)`, so the flag is appended to the `CC` and `CXX` commands (the compilers that `toolchain_identity()` records) as well as prepended to `LDFLAGS`; every link line starts with the compiler command. The staging path stays out of the cache identity. After the outputs are copied, `modsecurity_bundled_pcre2_blocker` verifies the header, the library and the ELF dynamic entries through `readelf -d`. `readelf` is now a required build tool. `MODSECURITY_OUTPUT_LAYOUT_VERSION` is 2 and the identity's `extra_inputs` gain `bundled_pcre2` (version, source URL, SHA-256, run path).

The host builds bind to the same libraries. The libModSecurity prefix is published before the hosts are built, so its `lib/` is a stable absolute run path. NGINX is configured with `--with-cc-opt=-I<prefix>/include` and `--with-ld-opt="-L<prefix>/lib -Wl,-rpath,<prefix>/lib"`. The Apache connector's `apxs` wrapper passes no `LDFLAGS` and links without `-rpath`, so `mod_security3.so` gets the prefix `lib/` through `LD_RUN_PATH` during `apache-make`. `httpd` is built inside the staging tree that is renamed on publication, so its run path is `$ORIGIN`-relative (`-Wl,-rpath,\$$ORIGIN/...` survives make, the shell and libtool). Both build scripts are already part of the connector source hash, so changing them rebuilds the host entries.

## Changed files and tests

- `connector_suite/modsecurity_connector_ci/provisioning/components/prepare-runtime-components.py`: bundled PCRE2 build, run-path verification, identity and fail-closed error paths.
- `connector_suite/modsecurity_connector_tests/test_runtime_component_cache_contract.py`: nine new on-demand tests (identity binding, `readelf` output parsing, configure and environment flags including the compiler prefix and `LDFLAGS` order, `$ORIGIN` verification against missing, staging and legacy run paths, failed ELF inspection, archive layout, unreadable archive, unexecutable PCRE2 and ModSecurity build tools, persisted verification failure); the staged-build test simulates the new PCRE2 stage; the layout-version test patches the current version plus one.
- `connector_suite/config/testing/active-cases.json`: source digest refreshed through `update-inventory-bindings.py --apply`; no active case was added or removed.
- `connector_suite/reports/testing/test-selection-archive.generated.json`: native generator refresh (`update-test-archive.py`) for the nine new on-demand tests; on-demand definitions 8476 to 8485, and `inventory_sha256` changes with the refreshed source digest.
- `ci/provisioning/prepare-nginx-build.sh`: compile and link NGINX against the bundled PCRE2 with a run path, verified by `readelf`.
- `ci/provisioning/prepare-apache-build.sh`: `$ORIGIN`-relative `httpd` run path and a `mod_security3.so` run path to the published libModSecurity, both verified by `readelf`.
- `docs/reference/variables.md`, `docs/reference/variables.de.md`: the PCRE2 row documents the bundled prefix and the run-path contract.
- `reports/audits/change-records/20261120-01-modsecurity-bundled-pcre2.md` and `.de.md`: this paired record.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `readelf -d` / `ldd` on the existing layout-1 prefix | 0 | No `RUNPATH`; NGINX, its module and libModSecurity resolved `libpcre2-8.so.0` to the distribution library. | Local diagnosis `devtest-20261119T093840Z` |
| `update-inventory-bindings.py --check`, then `--apply`, then `--check` | 1, 0, 0 | One drift (`prepare-runtime-components.py`), updated, then `INVENTORY_BINDINGS_VERIFIED`. | Local Framework validation |
| `ON_DEMAND_TESTS=1 python -P -m unittest` on `test_runtime_component_cache_contract` and `test_runtime_component_cache_identity` | 0 | 65 tests passed; an earlier run failed one staged-build test that did not yet simulate the PCRE2 stage. Explicit user approval for exactly these two archived modules. | Local Framework validation |
| `update-test-archive.py --check`, native generator, `--check` | 1, 0, 0 | Hosted `scaffold-lint` on the first push reported the stale archive; regenerated, then `Specialist archive matches current inventory and retained source definitions`. | Local Framework validation |
| SonarCloud pull-request analysis | 0 | Quality Gate passed with one new issue, `python:S8786` (super-linear backtracking in the `readelf` line regex). The overlapping `\s+[^\[]*` was replaced by disjoint character classes, and a test now parses real `readelf -d` output; the same expression was checked against the published library. The analysis of the host change reported eight `shell:S7679` issues (positional parameters used directly in the new `readelf` helpers); they now assign named variables and were re-tested against the published binaries. | Hosted Framework PR analysis |
| `make check-variable-documentation`, `make check-doc-links` | 0, 0 | Variable documentation and links passed. | Local Framework validation |
| `sonar analyze secrets --stdin` on every changed file | 0 | All selected inputs passed; raw scanner output suppressed. | Local Framework validation |
| `make prepare-runtime-components RUNTIME_COMPONENT_TARGET=all`, intermediate revision | 2 | PCRE2 10.49 built into the staging prefix; ModSecurity `configure` detected `PCRE2_VERSION=10.49` there and `libmodsecurity.so` linked; the bundled `modsec-rules-check` failed with undefined `pcre2_*@PCRE2_10.47` because `-L/usr/lib/<triplet>` preceded the bundle. This led to the `LDFLAGS` ordering. | Local run `pcre2-bundle-20261119` |
| Same target with the `LDFLAGS` ordering, inside a private mount namespace | 2 | `modsec-rules-check` now linked against the bundle; `examples/multithread` failed the same way because its per-target `multithread_LDFLAGS` precede `$(LDFLAGS)`. This led to the compiler-command prefix in the final revision. Only Go telemetry counters were redirected out of the home directory. | Local run `pcre2-bundle-r2-20261120` |
| Same target with the final revision, inside a private mount namespace with a read-only source checkout | 0 | libModSecurity published with `NEEDED libpcre2-8.so.0`, `DT_RUNPATH` exactly `$ORIGIN` and the pinned `libpcre2-8.so.0` (10.49, symbol versions `PCRE2_10.47` to `PCRE2_10.49`) in its own `lib/`; without `LD_LIBRARY_PATH` it resolves the bundled PCRE2. The Apache, NGINX and HAProxy connector builds completed against it. With the harness library paths, `httpd`, `mod_security3.so`, NGINX and its module resolve PCRE2, APR, APR-util and libModSecurity only from the external cache. Only Go telemetry counters were redirected; no build artifact appeared in either worktree. | Local run `pcre2-bundle-r3-20261120` |
| `make prepare-runtime-components RUNTIME_COMPONENT_TARGET=shared` with libModSecurity revision `cdfb668` in a fresh cache, private mount namespace | 0 | libModSecurity rebuilt from scratch with `DT_RUNPATH` `$ORIGIN`; the bundled PCRE2 resolves without `LD_LIBRARY_PATH`; nothing was redirected. | Local run `pcre2-bundle-final-20261120` |
| `ldd` without `LD_LIBRARY_PATH` on the layout-2 host builds before the host changes | 0 | `httpd` resolved the distribution PCRE2, APR and APR-util (loader version-mismatch warning), `mod_security3.so` the distribution libModSecurity 3.0.14, NGINX the distribution PCRE2. | Local diagnosis `pcre2-bundle-r3-20261120` cache |
| `make prepare-runtime-components RUNTIME_COMPONENT_TARGET=all` with the host changes | 2 | NGINX built and verified (`DT_RUNPATH` = published libModSecurity `lib/`); `httpd` passed its `$ORIGIN` run-path verification; the module verification rejected `mod_security3.so` without a run path, because `LDFLAGS` does not reach the connector's `apxs` link. This led to `LD_RUN_PATH` for `apache-make`. | Local run `pcre2-bundle-hosts-20261120` |
| `make prepare-runtime-components RUNTIME_COMPONENT_TARGET=apache`, final scripts | 0 | All Apache verifications passed. Without `LD_LIBRARY_PATH`, `httpd` resolves PCRE2, APR and APR-util through its `$ORIGIN` entries, and `mod_security3.so` and NGINX resolve libModSecurity and PCRE2 from the published prefix. With the harness paths everything also resolves from the cache. Nothing was redirected. | Local run `pcre2-bundle-apache2-20261121` |
| `make prepare-envoy-runtime`, `prepare-traefik-runtime`, `prepare-lighttpd-runtime` | 0, 0, 0 | Unaffected open-connector runtimes were provisioned. | Local run `pcre2-bundle-20261119` |

The libModSecurity revision `cdfb668` was rebuilt end to end in a fresh cache; the NGINX and Apache host scripts were verified in the two host runs above. The builds ran with Python 3.15.2, GCC 15.2.0, Parent revision `b79c3d93efbb8330f121caf8fb7c1a7874195e57` and this Framework base plus task changes. The cache, build, log and temporary roots were outside both Git worktrees.

## Security impact

The change removes a silent fallback to an unreviewed distribution library at runtime and keeps the existing literal-digest requirement for the PCRE2 archive. Publication now fails closed when the run path or the bundled library does not match the contract. No validation, authentication, isolation or redaction rule is weakened. Other libModSecurity dependencies (libxml2, curl, Lua, YAJL, MaxMindDB, ssdeep) still come from the distribution. The maintainer accepts this, because they are used only indirectly through libModSecurity.

## Documentation and runtime evidence

This English/German record pair and the English/German variable reference document the same scope. The local builds prove the provisioning layer only; no connector runtime smoke, lifecycle or matrix result is claimed.

## Checks not run

Hosted CI, a complete `quick-check`, the default `make test` suite, connector runtime smokes and the remaining archived on-demand catalogue have not run for this snapshot.

## Limitations and residual risk

HAProxy does not link PCRE2 itself and loads the bundle through libModSecurity. The lighttpd host binary still links `libpcre2-8.so.0` without a run path: its configure step adds `--without-pcre2` only when `configure --help` lists that literal flag, and lighttpd 1.4.85 lists `--with-pcre2`. This is unchanged here. Behind its two `$ORIGIN` entries, `httpd` keeps the absolute run paths libtool records for the staging tree; they no longer exist after publication and are never reached, because the `$ORIGIN` entries resolve first. The compiled-in NGINX and `httpd` installation prefixes still name the staging tree; the harnesses pass explicit paths. A host without `readelf` now blocks the libModSecurity, NGINX and Apache builds.

## Final diff and review status

The final diff contains the eight changed files and this record pair. Unit tests, inventory bindings, documentation checks, Secrets scans and the whitespace check passed. Framework delivery remains separate from Parent and MRTS delivery; the Parent Framework gitlink is unchanged and no merge is claimed.

Cache reuse now runs the existing bundled-PCRE2 verifier before accepting a complete entry. Missing PCRE2 headers or the runtime library, an invalid dependency entry, an unreadable ELF file, or an incorrect run path force a cache miss.

The existing staged-build test now removes both `include/pcre2.h` and `lib/libpcre2-8.so.0` after a successful cache hit and requires a fresh staged build for each. Before the correction, both cases incorrectly returned `reused`. After the correction, the explicit on-demand `RuntimeComponentCacheContractTest` class passed all 54 tests using the configured Framework Python 3.15.2 environment with external temporary storage. The native inventory-binding and test-archive generators refreshed their source digests. This follow-up provides cache-contract evidence. No additional runtime build was executed.
