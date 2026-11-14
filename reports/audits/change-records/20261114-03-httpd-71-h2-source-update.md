# Change record: HTTPD 2.4.71 H2 source update

**Language:** English | [Deutsch](20261114-03-httpd-71-h2-source-update.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20261114-03-httpd-71-h2-source-update` |
| UTC date | 2026-11-14 |
| Framework base revision | `b7caf33d6a151819527b5e713f9adb1991a1ac39` |
| Issue or pull request | Framework #169; Parent #445 is an external consumer |

## Motivation and problem statement

The selected external host run includes eight Apache-H2 cases. The Framework's
`connector_suite/adapters/apache/harness/apache_h2_acceptance.py` loads
`mod_http2.so`, selects `Protocols h2` and TLS 1.3, and invokes the H2 client.
The prior 2.4.70 source therefore reaches the module/protocol conditions of
[CVE-2026-119618](https://httpd.apache.org/security/json/CVE-2026-119618.json).
Apache lists versions 2.4.55–2.4.70 as affected and 2.4.71 as fixed. Loopback
and `H2Direct Off` do not remove the selected TLS-H2 source path.

## Affected components and security boundaries

This Framework change updates the reviewed HTTPD source tuple, immutable
checksum metadata and current-production regression expectations. Exact
provider, digest, private-cache and extraction controls remain enforced.
Parent runtime artifacts and integration decisions remain separately owned.

## Acceptance criteria

Two official HTTPS metadata sources agree; the actual archive matches their
digest; the existing cleanup patch applies strictly to released source; the
current helper admits that genuine private cache; all 20 recovery tests pass.

## Alternatives considered

Keeping 2.4.70 leaves the selected H2 source affected. The existing cleanup
patch changes `h2_mplx.c`, whereas the upstream CVE correction changes
`h2_request.c::assign_headers`; it cannot substitute for the release update.
Disabling H2 or weakening verification would change the selected contract.

## Implementation decision

Select 2.4.71, released on 2026-11-11 according to the
[official download page](https://httpd.apache.org/download.cgi). The independently
checked [immutable SVN object](https://dist.apache.org/repos/dist/!svn/bc/89368/release/httpd/httpd-2.4.71.tar.bz2.sha256)
and [archive metadata](https://archive.apache.org/dist/httpd/httpd-2.4.71.tar.bz2.sha256)
each returned HTTP 200 over verified TLS without redirects. Both contain the
same 87 bytes, SHA256
`70a701f5fb69bc96355859a4519bc00d17050135142ab57f5f7bf74a20eb7c8c`.
The actual archive contains 8618142 bytes and hashes to
`2bc5da5a33c247341de082717d4ebcb5cb49e8b73a05b7fddf7d5d6dc2f8de62`.

## Changed files and tests

- `ci/lib/common.sh`: HTTPD version and archive SHA256 literals.
- `ci/provisioning/httpd-checksum-cache.py`: immutable metadata URL and SHA256.
- `tests/security_regression/test_httpd_source_recovery.py`: independently
  reviewed current-production literals; the preceding 18 synthetic-fixture
  tests remain byte-identical. No test method is added or removed.
- This paired record; native generated inventories remain coordinator-owned.

## Commands and results

Commands below identify the executed entrypoints. Python selected the existing
Framework-owned Python 3.15.2; temporary/cache paths were external. Exact argv
and qualified receipts remain in the coordinating task's offline evidence.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk bypass python -B -m unittest tests.security_regression.test_httpd_source_recovery -v` | 0 | 20 passed in 89.470 seconds; zero failures, errors or skips | HTTPD71 source validation, 2026-11-14 |
| Current `ci/provisioning/httpd-checksum-cache.py` CLI with the genuine archive, checksum and exact `--downloaded-from` | 0 | `downloaded_verified_metadata`; real private cache admitted | Same offline run |
| `rtk bypass patch --dry-run --batch --forward --fuzz=0 -p1 -i` with `ci/provisioning/patches/apache/h2-joined-stream-purge.patch` | 0 | Released `h2_mplx.c` accepted without fuzz or offset; no source write | Same offline run |
| `rtk bypass git diff --check` | 0 | Source whitespace clean | Same offline run |

## Security impact

Released `h2_request.c::assign_headers` now writes the synthetic Content-Length
to `r->headers_in`, matching the upstream correction. Original-path source
inspection and strict cleanup-patch compatibility are separate from exploit
testing. Both CLI print modes and 16 mutated-tuple rejection controls pass
inside the existing production-contract tests. No path, ownership, single-link,
size, metadata, archive, TLS or redirect guard is relaxed.

## Documentation and runtime evidence

This English/German pair records the scoped source and offline results. No
Apache build, runtime artifact admission, service start, H2 exploitation,
92-case host run, CRS result or merge was performed by this change.

## Checks not run

Fresh build/host qualification and hosted CI/Sonar at the resulting commit are
coordinator work. Generated-inventory freshness and final documentation checks
remain pending that handoff. No local Sonar quality scanner was run.

## Limitations and residual risk

Archive/cache acceptance and source inspection do not prove compilation or
runtime safety. Fresh artifact provenance and selected host execution remain
required before any corresponding runtime claim.

## Final diff and review status

The coordinator approved the exact three-file source delta; scoped tests passed
and source hashes remained unchanged afterward. This record pair is handed back
for final bilingual, link, structural, Secrets and diff checks. No secrets or
raw sensitive material are recorded; no commit, merge or overall completion is
claimed.
