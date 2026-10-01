# Change record: pinned HTTPD source recovery

**Language:** English | [Deutsch](20261001-01-fix-httpd-source-recovery.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261001-01-fix-httpd-source-recovery |
| UTC date | 2026-10-01 |
| Framework base revision | 9181dc77dfb0685d87fa109e6800dc6052d77cc9 |
| Issue or pull request | [Framework PR #133](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/133); external integration consumer: Parent PR #370 |

## Motivation and problem statement

The canonical HTTPD 2.4.68 archive endpoint returns HTTP 404 while the official
Apache archive retains the identical release with the approved literal digest.
The Framework Apache preparer previously deleted an already verified staged
archive before retrying that unavailable URL. This Framework-owned acquisition
failure blocks the external Parent Apache source-build consumer.

## Affected components and security boundaries

`ci/provisioning/prepare-apache-build.sh` owns the HTTPD download-to-extraction
boundary. Network and cached bytes must retain the canonical reviewed source
identity, required digest, safe-root containment and TLS verification. Shared
downloader behavior, upstream pins, APR-util provenance and MRTS are unchanged.

## Acceptance criteria

Approved existing HTTPD archives are reverified without network attribution;
an absent archive can recover only after a direct canonical HTTP 404, from the
same official archive filename. Other failures remain blocking. Literal and
canonical metadata digests precede private-copy revalidation and extraction.
Focused positive, negative and caller-wiring regressions must pass; exact-head
Framework delivery checks remain separate from host-runtime acceptance.

## Alternatives considered

Changing canonical pins or disabling checksum metadata would alter the reviewed
identity or weaken validation. A generic fallback would broaden other
components' trust boundaries. Copying Framework provisioner logic into the
Parent would violate repository ownership. The narrow Apache HTTPD seam avoids
these changes.

## Implementation decision

Keep the reviewed tuple unchanged, validate it before cache/download operations,
reuse only a safe regular archive with a matching required literal digest, and
classify each fresh download independently. Only direct canonical HTTP 404
allows the official same-filename recovery endpoint. Record cache reuse or
actual transfer separately from canonical identity. Preserve metadata checks
and freeze/recheck the archive in the task-local build root before extraction.
APR and APR-util acquisition are unchanged.

## Changed files and tests

Apache preparer; focused `tests/security_regression/test_httpd_source_recovery.py`;
native Make target and lint wiring; paired `docs/development.md` /
`docs/development.de.md`; this paired Change Record. Tests cover canonical and
recovered downloads, cache integrity, error classification, provenance/path
guards, metadata enforcement and production call-chain behavior.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Bounded canonical HTTPD/APR/APR-util metadata preflight | 0 | HTTPD metadata redirects to the official archive and matches its literal; APR and APR-util metadata match their literal pins | pr370-ready-without-nginx-20261001 |
| `rtk proxy env HTTPD_RECOVERY_BASELINE=1` plus the two focused primary regressions at the immutable base | 1 (expected) | Both fail with the real bounded helper's HTTP 404/exit 77; verified-cache copy is not reused | framework-httpd-tests |
| `rtk proxy make test-httpd-source-recovery test-apr-util-provenance test-runtime-component-download` with explicit Framework Python and external roots | 0 | 18 HTTPD, 13 APR-util and 20 shared-download tests passed; independently rerun by the coordinator | framework-httpd-validation |
| `rtk proxy make test-runtime-component-lock test-runtime-component-sync check-canonical-common-pins test-makefile-contract test-ci-security-contract` with explicit Framework Python and external roots | 0 | Lock/sync/canonical/make checks passed; CI-security suite 308 tests passed | framework-httpd-validation |
| `rtk proxy sh framework-httpd-real-source-probe.sh` (task-owned external diagnostic) | 0 | Fresh official-archive recovery, literal/canonical metadata verification, private rehash and verified-cache reuse passed | framework-httpd-validation/real-source |
| `rtk proxy env TAR_OPTIONS=--no-same-owner timeout 600 sh framework-httpd-real-source-probe.sh --build-httpd` | 0 | Native HTTPD 2.4.68/APXS build passed; HTTPD/APR/APR-util literal and metadata checks preserved; system PCRE used for this diagnostic build only | framework-httpd-validation/real-source |
| `rtk proxy make check-documentation` with explicit Framework Python | 0 | Links, bilingual references, paths and Change Record checks passed | framework-httpd-validation |
| `rtk proxy sh -n ci/provisioning/prepare-apache-build.sh`; `rtk proxy git diff --check` | 0 | Syntax and whitespace passed; independent security diff review found no blocking defect | Framework worktree |

Commands above used the Framework-owned Python 3.14.7 environment; no packages
or pins were changed. A recovered first-attempt HTTP 404 diagnostic is not the
terminal result of the successful source-acquisition probe. That probe proves
archive integrity and handoff, not a host-runtime pass.

## Security impact

Availability repair at an existing security-sensitive acquisition boundary,
not remediation of a validated remotely exploitable vulnerability. No control
is suppressed. Required negative checks include unsafe paths, substituted
content, stale error classification, non-404 failures and metadata mismatch.

## Documentation and runtime evidence

The development guide and this Change Record have complete English/German
companions. No connector host-runtime or full-lifecycle evidence has been
collected by this Framework change; external Parent runtime CI is a separate
integration step. No connector readiness promotion is claimed.

## Checks not run

Full local `make lint` includes NGINX-specific regressions outside the current
user-selected scope; focused non-NGINX targets are used without weakening CI.
Full connector runtime and G1–G9 campaigns are not Framework acceptance evidence
and remain external Parent responsibilities. Generated reports are unchanged.
The first optional native build attempt exited 77 because this id-mapped
filesystem rejects archive UID/GID restoration; the safe `TAR_OPTIONS=--no-same-owner`
setting already used by the Parent profile allowed the recorded build retry.
No root-worker or runtime-permission workaround was introduced.

## Limitations and residual risk

Both approved upstream endpoints can become unavailable; non-404 failures remain
blocking. Cache reuse does not prove a new transfer. Framework source/tests and
CI do not themselves prove the external consumer's host behavior.

## Final diff and review status

Focused implementation checks and independent security diff review passed.
The final scoped diff and whitespace were reviewed; no pins, shared downloader,
APR-util, NGINX or MRTS changes are present. Separate Framework commit/push/PR
delivery exists at PR #133. The first published head was
`1dc8e3e29017fd8cb7f424ba127bc00cb8bc4695`; observed Sonar analysis at
`2026-10-01T17:36:26+0000` bound to that head and returned Quality Gate OK,
0.0% new duplication, zero open/confirmed issues and zero pending hotspots.
Hosted checks were still running at this record update; this documentation
follow-up requires its own fresh exact-head verification. External Parent
integration remains pending. No merge was performed. Only task-owned Framework
changes will be staged; no secrets, raw bodies or unrestricted logs are recorded.
