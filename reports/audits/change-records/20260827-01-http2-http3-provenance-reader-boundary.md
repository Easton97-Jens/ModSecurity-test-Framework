# Change record

**Language:** English | [Deutsch](20260827-01-http2-http3-provenance-reader-boundary.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260827-01-http2-http3-provenance-reader-boundary` |
| UTC date | 2026-08-27 |
| Framework base revision | `86451b45ae7bb7953baf9f81f2c2dad07395a808` |
| Issue or pull request | Parent Draft PR `#348` remains unchanged; Framework Draft PR `#112` is open and remains separate. |

## Motivation and problem statement

The user authorized Framework work because `ci/lib/common.sh` owns the
reviewed component versions needed by the Parent HTTP/1.1, HTTP/2, and
HTTP/3 parity workstream. OpenSSL 4.0.1 had an NGINX-specific duplicate tuple
even though it is a generic source identity. AWS-LC had no canonical record,
despite a user-supplied immutable tag/commit identity for future evaluated
use. Separately, selected protocol sidecar and evidence files were read in
full before their configured size bounds and regular-file checks were applied.

## Affected components and security boundaries

- `ci/lib/common.sh` is the sole Framework authority for active source
  identities and their inherited/post-source active-pin controls.
- `ci/tools/check-common-versions.py` validates canonical ownership, immutable
  GitHub tag/commit provenance, OpenSSL release assets, and derived aliases.
- `ci/checks/protocol/protocol_client.py` and
  `ci/checks/protocol/check_protocol_evidence.py` consume caller-selected
  sidecar/evidence paths at a file-read boundary.
- The English/German variable references describe Framework metadata only.

No connector build selection, AWS-LC acquisition, curl/ngtcp2/nghttp3
provisioning, Parent Gitlink, MRTS content, workflow credential, or runtime
promotion changes here.

## Acceptance criteria

1. The generic OpenSSL tuple records `4.0.1`, `openssl-4.0.1`, the official
   release asset URL, and the user-supplied SHA-256; NGINX aliases derive from
   that one tuple.
2. The AWS-LC repository, `v5.5.0` tag, and full peeled commit are canonical,
   immutable metadata; an independent repository-identity hash rejects a
   substituted GitHub repository before any upstream lookup.
3. Exported inherited OpenSSL overrides and post-source AWS-LC mutations fail
   closed with the repository's blocked status; the default H1 profile stays
   unchanged.
4. Protocol readers consume only descriptor-walked, non-symlink, regular files
   and retain at most the configured bound plus one byte.
5. EN/DE documentation, focused tests, and canonical validation agree without
   asserting an unrun HTTP/2 or HTTP/3 runtime.

## Alternatives considered

- Retaining a second NGINX-only OpenSSL identity was rejected because two
  active literals can drift while appearing to describe the same source.
- Enabling AWS-LC as an NGINX TLS library was rejected: current provisioning
  explicitly supports OpenSSL only, and the user did not authorize or provide
  a reviewed build/runtime design for AWS-LC.
- Treating a mutable AWS-LC tag as sufficient was rejected; the tag is bound to
  the supplied full commit by the `github_tag_commit` checker contract.
- Path pre-checks followed by whole-file reads were rejected because they allow
  special-file blocking, unbounded allocation, and path replacement races.

## Implementation decision

`OPENSSL_*` is now the canonical release tuple. The existing
`NGINX_QUIC_TLS_*` values are derived aliases, and the checker verifies that
relationship before any resolver lookup. `AWS_LC_*` records provenance only:
its parsed repository must match an independent approved-identity hash before
lookup, and it is explicitly not a selected library or a verified capability.

The reader boundary opens each directory component without following symlinks,
opens the final file nonblocking and no-follow, requires `fstat()` to identify
a regular file, and reads no more than `maximum + 1` bytes. Existing callers
map invalid, unavailable, and oversized input to their established errors.

## Changed files and tests

- `ci/lib/common.sh`
- `ci/tools/check-common-versions.py`
- `ci/checks/protocol/protocol_client.py`
- `ci/checks/protocol/check_protocol_evidence.py`
- `tests/security_regression/test_common_version_atomic_provenance.py`
- `tests/security_regression/test_common_shell_sonar_contracts.py`
- `tests/protocol_client/test_protocol_client.py`
- `tests/protocol_client/test_check_protocol_evidence.py`
- `docs/reference/variables.md`
- `docs/reference/variables.de.md`
- this paired English/German Change Record

Focused negative coverage includes canonical copied-pin rejection, substituted
AWS-LC repository and malformed-commit rejection, all four OpenSSL alias
divergences, inherited and post-source pin mutation, final and ancestor
symlinks, FIFOs, oversized files, and normal H3 observation parsing.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy git ls-remote https://github.com/aws/aws-lc.git 'refs/tags/v5.5.0*'` | 0 | The supplied AWS-LC tag resolved to `991e67ff4cf04df4dd89e407f8b920c6936cb56a`. | Task transcript, 2026-08-27 |
| `rtk proxy sh -n ci/lib/common.sh` | 0 | The modified canonical shell source parses. | Isolated Framework worktree |
| `rtk proxy python3 -B ci/tools/check-common-versions.py --validate-canonical` | 0 | Canonical local pin contract passes without an HTTP lookup. | Isolated Framework worktree |
| `rtk proxy python3 -B -m unittest tests.security_regression.test_common_version_atomic_provenance -v` | 0 | 27 provenance-contract tests pass. | Isolated Framework worktree |
| `rtk proxy python3 -B -m unittest tests.security_regression.test_common_shell_sonar_contracts -v` | 0 | 8 shell-boundary tests pass, including inherited/post-source mutation controls. | Isolated Framework worktree |
| `rtk proxy python3 -B -m unittest tests.protocol_client.test_protocol_client tests.protocol_client.test_check_protocol_evidence -v` | 0 | 31 bounded-reader and protocol-client tests pass. | Isolated Framework worktree |
| `rtk proxy python3 -B ci/checks/documentation/check-variable-documentation.py` | 0 | English/German variable-reference parity passes. | Isolated Framework worktree |
| `rtk proxy git diff --check` | 0 | No whitespace errors in the scoped diff. | Isolated Framework worktree |

## Security impact

The change removes a source-identity duplication, binds the user-supplied
AWS-LC repository/tag to an independent repository identity and full immutable
commit, and turns the relevant protocol file reads into bounded regular-file
reads. An independent post-fix review exercised ancestor/final symlink and
FIFO races without an escape or blocking path.

It does not solve the separately identified evidence-integrity limitations:
strict H3 sidecar transport/reset fields remain self-attested, TLS
`--insecure` provenance is not encoded in the evidence, and current client
selection/PATH provenance is a hardening/reproducibility gap. None is claimed
fixed or promoted by this record.

## Documentation and runtime evidence

The English and German variable references document the same OpenSSL/AWS-LC
ownership and explicitly state that AWS-LC is not a current build selection.
No connector, HTTP/2, HTTP/3, QUIC, AWS-LC, or MRTS runtime was started in this
Framework worktree. The Parent must obtain separate exact-head runtime evidence
after an explicit Gitlink decision.

## Checks not run

- No AWS-LC download, build, installation, or NGINX library selection was run;
  that implementation is out of scope for this provenance record.
- No managed curl/ngtcp2/nghttp3 provisioning was attempted because required
  reviewed versions, assets, checksums, and policy are not supplied.
- Full Framework test/lint matrices, hosted CI, SonarCloud, and the Framework
  Draft PR checks are pending delivery.
- No Parent or MRTS test was run and no Parent Gitlink was changed.

## Limitations and residual risk

The pin contract proves reviewed source identity only; it cannot make an
unimplemented AWS-LC build usable or prove HTTP/3 support. A non-security
robustness edge remains in the reader helper: resolving a relative path after
the process current working directory has been deleted can raise before the
existing caller-specific error mapping. All known production callers use
configured artifact paths; this is documented rather than silently broadened
in this change.

## Final diff and review status

At record creation, all changes are confined to the external task-owned
Framework worktree and remain unstaged pending final scoped diff, secret, and
independent provenance review. No commit, push, pull-request creation, merge,
Parent Gitlink movement, or MRTS action has occurred. The authorized next
delivery step is a separate Framework Draft PR only.

**SonarQube Cloud remediation (candidate).**

At exact Framework Draft PR `#112` head
`630449ed71cadb0915dd82e1831aa08700fbdc2a`, SonarQube Cloud reported the
new issue `AaBC6hWexbnbqiQBrl8d`, rule `python:S3776`, on
`resolve_component_definition`: cognitive complexity `17` where `15` is
allowed. The Quality Gate was `OK`, but the current user explicitly requested
that the new issue be repaired.

The candidate splits the existing generic resolver body into
`resolve_standard_component_definition`. `resolve_component_definition` still
dispatches CRS and ModSecurity v3 first, then delegates every other descriptor
to the unchanged body. In particular, GitHub repository canonicalization and
its `STATUS_BLOCKED` conversion remain before all network-backed resolver
calls; no rule, Quality-Gate, workflow, suppression, exclusion, pin, Parent
Gitlink, or MRTS change is part of this remediation.

**Added regression coverage and local validation.**

`tests/security_regression/test_common_version_atomic_provenance.py` now
checks that the two specialized components bypass the standard dispatcher, a
GitHub canonicalization failure remains blocked before a resolver can use the
client, and an unknown strategy retains its `UpstreamError` message.

| Command | Exit code | Concise result | Evidence |
| --- | --- | --- | --- |
| `rtk proxy python3 -B -m unittest -v tests.security_regression.test_common_version_atomic_provenance` | 0 | 30 hermetic provenance tests pass, including the three new dispatcher controls. | Isolated Framework worktree, 2026-08-27 |
| `rtk proxy python3 -B -m unittest -v tests.security_regression.test_common_version_descriptor_series tests.security_regression.test_crs_git_ref_provenance.FetchCrsProvenanceTests.test_version_checker_automatically_updates_only_the_crs_v4_tuple tests.security_regression.test_crs_git_ref_provenance.FetchCrsProvenanceTests.test_version_checker_repairs_a_stale_crs_rule_digest tests.security_regression.test_crs_git_ref_provenance.FetchCrsProvenanceTests.test_version_checker_rejects_an_invalid_candidate_rule_file tests.security_regression.test_crs_git_ref_provenance.FetchCrsProvenanceTests.test_version_checker_rejects_foreign_crs_repository_before_network tests.security_regression.test_common_versions_sonar_provenance.CommonVersionProvenanceTests.test_modsecurity_v3_release_requires_reviewed_tag_and_commit_pair tests.security_regression.test_common_versions_sonar_provenance.CommonVersionProvenanceTests.test_modsecurity_v3_release_blocks_missing_or_malformed_immutable_anchor tests.security_regression.test_common_versions_sonar_provenance.CommonVersionProvenanceTests.test_unknown_results_fail_closed_while_local_policy_entries_are_not_applicable` | 0 | 11 descriptor, CRS, ModSecurity-v3, and alternate-result controls pass. | Isolated Framework worktree, 2026-08-27 |
| `rtk proxy python3 -B ci/tools/check-common-versions.py --validate-canonical` | 0 | Offline canonical `common.sh` pin contract passes. | Isolated Framework worktree, 2026-08-27 |
| `rtk proxy git diff --check` | 0 | No scoped whitespace errors. | Isolated Framework worktree, 2026-08-27 |

Two independent read-only reviews traced the pre- and post-patch resolver
paths. The post-patch review found no new validated security or compatibility
finding: CRS/ModSecurity-v3 ordering, canonicalization-before-network,
`STATUS_BLOCKED` conversion, all other strategy branches, and `check_all`
exception mapping are retained. The review noted a pre-existing, out-of-scope
NGINX repository-identity design concern for separate triage; it was not
introduced or changed by this refactor.

**Delivery evidence boundary.**

The local candidate was validated before normal successor delivery. A fresh
Framework PR `#112` successor must be verified by exact local/remote/PR-head
SHA, current SonarQube Cloud issue query, Quality Gate, and applicable hosted
checks before this record or the finding can be marked fixed. Full Framework
`make lint` and broader matrices were not run for this narrow dispatch
refactor; `ruff` is not installed locally and no dependency installation was
performed. No runtime, Parent, or MRTS validation is implied.
