# Change record: 20260814-01-harden-runtime-component-provisioning

**Language:** English | [Deutsch](20260814-01-harden-runtime-component-provisioning.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260814-01-harden-runtime-component-provisioning` |
| UTC date | 2026-08-14 |
| Framework base revision | `1260aaae411ecf88cf50dc480b80e2e20ac47901` |
| Issue or pull request | Draft PR pending. No issue is closed. Addresses F-GS-004. |

## Motivation and problem statement

F-GS-004 identified version drift between Framework runtime metadata and
consumers, including Envoy `1.38.2` versus `1.39.0`, Traefik `3.7.5` versus
`3.7.10`, and a generic HAProxy version that must not replace the exact
HAProxy HTX `3.2.21` runtime. The common downloader also had no bounded
connect or total timeout, could retain empty or checksum-invalid artifacts,
and emitted complete caller-controlled URLs in some blocked diagnostics.

## Affected components and security boundaries

The Framework-only scope covers the reviewed runtime lock, common runtime
artifact downloader, HAProxy source preparer, NGINX archive provisioner,
Apache source provisioner, their local regression tests, and the checked
manifest. The boundary begins with a reviewed HTTPS release tuple and ends
only after a non-empty artifact passes its required SHA-256 check. Parent,
Parent Gitlink, connector host claims, MRTS, global installs, and deployment
remain outside this change.

## Acceptance criteria

1. The lock contains NGINX, HAProxy HTX, HAProxy SPOE/SPOP, Envoy `ext_authz`,
   Envoy `ext_proc`, Traefik `forwardauth`, and native Traefik tuples.
2. The checker blocks the known NGINX `1.31.2`, Envoy `1.38.2`, and Traefik
   `3.7.5` drift, incorrect architecture/asset values, and missing or invalid
   SHA-256 values.
3. HAProxy HTX remains exactly `3.2.21` with
   `0cb8818a26c5f888e0cb1c40f1b3acb9fb952527d1733f769ce688fedd680339`,
   independently of HAProxy SPOE/SPOP `3.2.22`.
4. Downloads retain TLS verification, use bounded connect/total/retry time,
   classify failures safely, and remove empty, partial, missing-pin, and
   checksum-invalid artifacts before they can be staged.
5. Local failure fixtures and a legitimate verified-download control pass
   without network access or a global installation.

## Alternatives considered

- Duplicating version tuples in each provisioner was rejected because it
  recreates the drift boundary.
- Retrying all curl failures was rejected because TLS, permanent HTTP, SHA,
  and configuration failures need remediation rather than repeated requests.
- Retaining a failed artifact for diagnosis was rejected because a stale
  partial or checksum-invalid file could later be staged as trusted input.

## Implementation decision

`ci/provisioning/runtime-component-lock.json` is the canonical reviewed lock.
`ci/tools/check-runtime-component-lock.py` validates the common defaults and
the Envoy/Traefik inventory manifest against it; normal `make lint` runs that
check and its regression suite. Runtime provisioners validate their effective
NGINX, Envoy, Traefik, generic HAProxy, and HAProxy HTX environment tuple
before accepting a local binary or an opt-in download. The HTX tuple is represented by the separate
`HAPROXY_HTX_*` variables and cannot use generic `HAPROXY_VERSION` metadata.

The shared downloader invokes curl with leading `--disable` so ambient curl
configuration cannot weaken the reviewed flags. It uses HTTPS-only curl with
`--connect-timeout`, `--max-time`, bounded retry time, temporary files from
`mktemp`, metric capture, HTTPS-only redirect protocols, and no insecure
option. Caller-supplied timeout values must be positive integers within the
reviewed connect (`60` seconds), total (`900` seconds), and retry (`300`
seconds) bounds; retry time may not exceed the total timeout. It emits a
sanitized machine-readable `runtime_diagnostic` with status `BLOCKED`, a
stable reason code, safe host, artifact identifier, remediation, and truthful
`tls_verification` (`verified`, `failed`, `not_confirmed`, or
`not_attempted`). The HAProxy source preparer, NGINX archive provisioner, and
Apache/PCRE2/APR/APR-util provisioners reuse the bounded verified transfer.
APR-util retains the reviewed no-redirect mode. URL userinfo and query content
are not retained in diagnostics, including rejected HTTPS URL checks.

## Changed files and tests

- `ci/lib/common.sh` defines and exports the exact HAProxy HTX tuple.
- `ci/provisioning/runtime-component-lock.json` defines the canonical profile
  lock; `runtime-components.manifest.json` now matches Envoy `1.39.0` and
  Traefik `3.7.10`.
- `ci/tools/check-runtime-component-lock.py` validates tuple, platform,
  asset, download URL, SHA-256, provenance, and manifest drift.
- `ci/lib/runtime-component-common.sh` hardens bounded transfers, curlrc
  isolation, timeout-policy validation, diagnostics, cleanup, no-redirect
  mode, and integrity handling; `prepare-haproxy-runtime.sh`,
  `prepare-nginx-build.sh`, and `prepare-apache-build.sh` use it.
- `tests/security_regression/test_runtime_component_lock.py` and
  `test_runtime_component_download.py` cover drift, effective-tuple
  enforcement, timeout-policy rejection, failure fixtures, cleanup, redaction,
  and the legitimate staging path.
- `tests/security_regression/test_nginx_archive_digest.py` exercises the NGINX
  archive cache and provenance contract through the shared downloader.
- `tests/security_regression/test_apr_util_provenance.py` retains the APR-util
  no-redirect contract through the shared downloader.
- `Makefile` provides the focused lock and download targets and includes them
  in normal lint.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `sh -n ci/lib/common.sh ci/lib/runtime-component-common.sh ci/provisioning/prepare-haproxy-runtime.sh ci/provisioning/prepare-nginx-build.sh ci/provisioning/prepare-envoy-runtime.sh ci/provisioning/prepare-traefik-runtime.sh` | 0 | Changed shell files passed syntax validation. | `f-gs-004-framework-20260814` |
| `python3 -m json.tool ci/provisioning/runtime-component-lock.json` | 0 | Canonical lock is valid JSON. | `f-gs-004-framework-20260814` |
| `make BUILD_ROOT=<task-owned-external-root>/build TMP_ROOT=<task-owned-external-root>/tmp test-runtime-component-lock` | 0 | Checker plus eight deterministic lock-drift and effective-environment tests passed. | `f-gs-004-framework-20260814` |
| `make BUILD_ROOT=<task-owned-external-root>/build TMP_ROOT=<task-owned-external-root>/tmp test-runtime-component-download` | 0 | Ten local download failure/control, timeout-policy, curlrc-isolation, TLS-status, redaction, no-redirect, and preparer-adoption tests passed. | `f-gs-004-framework-20260814` |
| `make BUILD_ROOT=<task-owned-external-root>/build TMP_ROOT=<task-owned-external-root>/tmp test-apr-util-provenance` | 0 | Thirteen APR-util provenance/no-redirect regression tests passed after shared-downloader adoption. | `f-gs-004-framework-20260814` |
| `make BUILD_ROOT=<task-owned-external-root>/build TMP_ROOT=<task-owned-external-root>/tmp test-nginx-archive-digest` | 0 | Twenty-one NGINX archive cache, provenance, HTTPS-only redirect, lock, checksum, and extraction regressions passed through the shared downloader. | `f-gs-004-framework-20260814` |
| `shellcheck -x ci/lib/runtime-component-common.sh` | 0 | The changed shared downloader has no ShellCheck findings. | `f-gs-004-framework-20260814` |
| `make BUILD_ROOT=<task-owned-external-root>/lint-build-final TMP_ROOT=<task-owned-external-root>/lint-tmp-final lint` | 0 | The complete Framework lint and contract suite passed after the Apache, lock-enforcement, and TLS-status hardening. | `f-gs-004-framework-20260814` |

## Security impact

The focused remediation uses controlled fake-curl inputs to reproduce DNS,
connect, timeout, TLS, HTTP, empty, partial, and checksum-invalid failures.
Each failure removes the candidate artifact and leaves a `BLOCKED` diagnostic;
the valid control verifies and stages a non-empty matching artifact. The
alternate bypass classes of URL userinfo/query redaction, invalid-URL
rejection, APR-util redirects, ambient curl configuration, and unbounded or
zero timeout overrides are covered. TLS and SHA-256 enforcement were
strengthened, not relaxed; a TLS failure reports `tls_verification=failed`
rather than a false success. No secret, token, private URL, or
network-downloaded artifact is recorded.

## Documentation and runtime evidence

This paired Change Record documents the Framework decision in English and
German. The tests are local helper and lock-contract evidence only. No NGINX,
HAProxy, Envoy, or Traefik host process was started, so no hostruntime `PASS`
is claimed. Parent consumes this lock only after its separate dependency and
Gitlink lifecycle are authorized.

## Checks not run

- A real external component download was not run: the local fixture matrix is
  deterministic and avoids uncontrolled network acquisition.
- Parent-owned NGINX, HAProxy SPOE/SPOP, Envoy, and Traefik host tests were
  not run in this Framework change; missing host infrastructure remains a
  component-specific `BLOCKED` condition, not `FAIL`.

## Limitations and residual risk

The checker protects the reviewed Linux amd64 profile contract; a new
operating-system or architecture profile needs its own reviewed tuple and
test. Curl's default retry policy is intentionally not broadened with
`--retry-all-errors`; upstream behavior remains an external dependency.
The Framework Draft PR is not merged, therefore the Parent Gitlink is
unchanged and the lock is not yet present in Parent's recorded submodule
revision.

## Final diff and review status

The task-owned diff, whitespace, secret, and documentation reviews passed
after the final hardening before delivery. No commit, push, PR, merge, Parent
change, MRTS change, or Gitlink update is claimed by this record.
