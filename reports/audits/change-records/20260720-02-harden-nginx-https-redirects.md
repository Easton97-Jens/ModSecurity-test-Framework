# 20260720-02-harden-nginx-https-redirects — HTTPS-only NGINX download redirects

**Language:** English | [Deutsch](20260720-02-harden-nginx-https-redirects.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260720-02-harden-nginx-https-redirects |
| UTC date | 2026-07-20 |
| Framework base revision | 784977615acfc55567e37b863309abc4a38ac877 |
| Issue or pull request | SonarCloud AZ9_o2_jSLr5VHr-smcj (shell:S6506); task-branch delivery is pending and no merge is authorized. |

## Motivation and problem statement

The current default-branch SonarCloud analysis reported a redirect-following
GitHub latest-release lookup without an explicit HTTPS protocol contract. The
release-asset and HTTP/3 TLS-source download paths used the same Curl pattern.
A provisioning request must not follow a redirect to HTTP or another protocol.

## Affected components and security boundaries

The Framework-only transport boundary includes:

- ci/provisioning/prepare-nginx-build.sh
- tests/security_regression/test_nginx_archive_digest.py
- Makefile

The change constrains redirect protocols while preserving the independent
pinned SHA-256 check before archive extraction. It changes no Parent,
connector, gitlink, or MRTS content.

## Acceptance criteria

- Every redirect-following NGINX Curl call explicitly permits HTTPS only for
  initial and redirect protocols.
- The local real-script harness rejects the old call form and accepts
  deterministic GitHub API and release-archive HTTPS controls.
- The HTTP/3 TLS download receives the same source contract.
- Direct tests cover existing /tmp, snapshot, runner, and case-information
  output-containment controls.
- No SonarCloud rule, profile, gate, exclusion, accepted issue, or NOSONAR
  setting changes.

## Alternatives considered

Removing redirect following from the latest-release lookup would change existing
cache and endpoint behavior. Restricting only the reported metadata call would
leave two equivalent provisioning paths unconstrained. An HTTPS-only protocol
restriction preserves expected GitHub/CDN HTTPS redirects and directly enforces
the reported transport invariant.

Changing analyzer configuration or accepting an issue was rejected because it
would not enforce the transport boundary.

## Implementation decision

Each redirect-following Curl call now contains:

~~~text
--proto =https --proto-redir =https
~~~

The latest-release command record matches the executed command. The regression
harness captures both option values and fails when either is absent. Its
dynamic control covers the latest metadata and chosen release asset, and its
source-contract control requires the same pair on all three current Curl calls,
including the HTTP/3 TLS archive.

The named Make target test-nginx-archive-digest was added to lint so this
transport contract remains project-native.

## Changed files and tests

- ci/provisioning/prepare-nginx-build.sh
- Makefile
- tests/security_regression/test_nginx_archive_digest.py
- tests/no_crs/test_no_crs_baseline.py
- tests/security_regression/test_runtime_snapshot_sonar.py
- tests/security_regression/test_runner_core_output_containment.py
- this English/German Change Record pair

The NGINX regression failed before the patch because fake Curl required both
HTTPS option values, then passed after the patch. The added containment controls
reject /tmp, a mismatched snapshot destination, and an out-of-root
case-information output while preserving legitimate contained writes.

## Commands and results

All tests used an existing Framework virtual environment plus task-owned
external build and temporary roots. task_run_root below denotes that configured
external root, not a repository path.

~~~text
C01 rtk run 'PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX="$task_run_root/build/pycache" TMPDIR="$task_run_root/tmp" "$framework_python" -m unittest discover -s tests/security_regression -p test_nginx_archive_digest.py -v'
C02 rtk run 'PYTHONNOUSERSITE=1 PYTHON="$framework_python" BUILD_ROOT="$task_run_root/build" TMP_ROOT="$task_run_root/tmp" LOG_ROOT="$task_run_root/logs" make test-nginx-archive-digest'
C03 rtk run 'sh -n ci/provisioning/prepare-nginx-build.sh'
C04 rtk run 'curl --proto =https --proto-redir =https --version'
C05 rtk run 'PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX="$task_run_root/build/no-crs/pycache" TMPDIR="$task_run_root/tmp/no-crs" "$framework_python" tests/no_crs/test_no_crs_baseline.py -v'
C06 rtk run 'PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX="$task_run_root/build/runtime-snapshot/pycache" TMPDIR="$task_run_root/tmp/runtime-snapshot" "$framework_python" tests/security_regression/test_runtime_snapshot_sonar.py -v'
C07 rtk run 'PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX="$task_run_root/build/runner-containment/pycache" TMPDIR="$task_run_root/tmp/runner-containment" "$framework_python" tests/security_regression/test_runner_core_output_containment.py -v'
C08 rtk curl 'https://sonarcloud.io/api/issues/search?organization=easton97-jens&componentKeys=Easton97-Jens_ModSecurity-test-Framework&branch=master&resolved=false&ps=100&p=1'
C09 rtk curl 'https://sonarcloud.io/api/qualitygates/project_status?projectKey=Easton97-Jens_ModSecurity-test-Framework&branch=master'
C10 rtk run 'PYTHONNOUSERSITE=1 PYTHON="$framework_python" PYTHONPYCACHEPREFIX="$task_run_root/build/lint/pycache" TMPDIR="$task_run_root/tmp/lint" BUILD_ROOT="$task_run_root/build/lint" TMP_ROOT="$task_run_root/tmp/lint" LOG_ROOT="$task_run_root/logs/lint" FRAMEWORK_ROOT="$task_worktree" CONNECTOR_ROOT="$task_worktree" OUTPUT_ROOT="$task_worktree" CI_ROOT="$task_worktree/ci" make lint'
~~~

| Command ID | Exit code | Concise result | Run ID |
| --- | --- | --- | --- |
| C01 | 1 before patch; 0 after patch | Old transport form failed only on absent option values; 11 focused archive tests then passed. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C02 | 0 | Native Make target ran 12 archive/redirect controls successfully. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C03 | 0 | POSIX shell syntax passed. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C04 | 0 | Installed Curl 8.18.0 accepted both protocol options. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C05 | 0 | 75 No-CRS tests passed, including direct /tmp rejection. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C06 | 0 | Focused snapshot-containment controls passed. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C07 | 0 | Focused runner and case-information containment controls passed. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C08 | 0 | Current master reports 23 open rows: six Framework and 17 MRTS metadata-only rows. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C09 | 0 | Current master Quality Gate is ERROR only on new_security_rating=5 against threshold 1. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |
| C10 | 0 | Replacement full lint passed with every Framework/connector/output root explicitly bound to the isolated task worktree; its final `git diff --check` also passed. | 20260720T161432Z-master-post36-sonar-remediation-0ff399e8 |

## Security impact

The repair prevents an HTTPS-origin NGINX provisioning request from following a
redirect to HTTP or a non-HTTPS protocol. The original metadata and
release-asset paths passed the legitimate HTTPS control after the patch, and
the HTTP/3 TLS call is covered by the same contract.

This is a protocol-downgrade control. It does not claim a redirect-host
allowlist or a general SSRF remediation. Existing pinned-digest verification
continues to protect the selected archive before extraction.

The fresh SonarCloud readback retained five older Framework security signals:

| Key | Rule | Reported sink | Current source/control disposition |
| --- | --- | --- | --- |
| AZ9cRqtu1JCbMyYXCAue | python:S5443 | ci/checks/catalog/no_crs_baseline.py:1746 | /tmp, public parents, symlink components, and source checkouts are rejected before a run root is used. |
| AZ7Wh-x6WJ9AQTOMyhFJ | pythonsecurity:S8707 | ci/reporting/update-runtime-snapshot.py:72 | Snapshot target must equal the canonical report snapshot beneath the selected output root. |
| AZ5Q3NAAoI4Cm-ZmWjGX | pythonsecurity:S2083 | ci/reporting/update-runtime-snapshot.py:72 | The same canonical snapshot-target guard applies. |
| AZ55dzzC6nhd5cS8C48e | pythonsecurity:S2083 | tests/runners/runner_core.py:636 | contained_write_path rejects an output outside its trusted root before writing. |
| AZ6jf1K_DIaptS4_Hf5n | pythonsecurity:S2083 | tests/runners/case_cli.py:424 | case-info uses the same guard and a required trusted output root. |

Official flows for the latter four rows show tainted content reaching a write
API, not a bypass of the path-containment controls. The rows remain open in the
external analyzer; no false-positive, suppression, or accepted-issue action was
taken.

## Documentation and runtime evidence

This English/German pair documents the Framework-only patch. Local finding
records retain the Framework inventory, the 17 external MRTS metadata rows, and
the separate evidence-gap candidate. No connector runtime, network download, or
MRTS source test was collected.

The MRTS rows are documented from official metadata only:

| Key | Rule | Reported location |
| --- | --- | --- |
| AZ84XDED2YUGB8FZMhlf | python:S3776 | tools/MRTS/mrts/generate-rules.py:122 |
| AZ84XDED2YUGB8FZMhlg | python:S7504 | tools/MRTS/mrts/generate-rules.py:139 |
| AZ84XDED2YUGB8FZMhlh | python:S108 | tools/MRTS/mrts/generate-rules.py:167 |
| AZ84XDED2YUGB8FZMhli | python:S3776 | tools/MRTS/mrts/generate-rules.py:182 |
| AZ84XDED2YUGB8FZMhlj | python:S3776 | tools/MRTS/mrts/generate-rules.py:208 |
| AZ84XDED2YUGB8FZMhlk | python:S8519 | tools/MRTS/mrts/generate-rules.py:336 |
| AZ84XDED2YUGB8FZMhll | python:S8519 | tools/MRTS/mrts/generate-rules.py:343 |
| AZ84XDED2YUGB8FZMhlm | pythonsecurity:S8707 | tools/MRTS/mrts/generate-rules.py:428 |
| AZ84XDED2YUGB8FZMhln | pythonsecurity:S8707 | tools/MRTS/mrts/generate-rules.py:444 |
| AZ84XDED2YUGB8FZMhlX | python:S1940 | tools/MRTS/mrts/mrts.py:93 |
| AZ84XDDw2YUGB8FZMhle | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:13 |
| AZ84XDDw2YUGB8FZMhlb | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:14 |
| AZ84XDDw2YUGB8FZMhlY | pythonsecurity:S8705 | tools/MRTS/mrts/mrts.py:30 |
| AZ84XDDw2YUGB8FZMhlc | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:30 |
| AZ84XDDw2YUGB8FZMhlZ | pythonsecurity:S8705 | tools/MRTS/mrts/mrts.py:53 |
| AZ84XDDw2YUGB8FZMhld | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:73 |
| AZ84XDDw2YUGB8FZMhla | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:83 |

## Checks not run

No connector runtime matrix, external archive download, MRTS source inspection,
MRTS test, default-branch integration, or merge was run. An earlier lint
attempt inherited Parent root variables and was deliberately interrupted; it is
recorded as `FND-CROSS-0002` and is not treated as passing validation. C10 is
the replacement result with explicit isolated roots. A new exact-head SonarCloud
analysis is pending normal task-branch delivery; current master analysis cannot
evaluate this unmerged change.

## Limitations and residual risk

Current master remains red because five historical Framework security rows and
17 externally owned MRTS metadata rows remain open. Framework controls provide
concrete counterevidence for the reported write-path risk, but cannot change
the external analyzer status. A post-delivery master verification needs separate
integration authorization; this task has no merge authority. The recorded
interrupted lint boundary incident cannot be retroactively erased, although its
explicit-root replacement passed; the overarching task therefore cannot claim a
fully clean cross-repository boundary history.

## Final diff and review status

Focused tests, explicit-root full lint, and `git diff --check` have passed.
Pending are the final scoped/security review, normal task-branch commit, push,
Draft PR, and exact-head remote readback. No Parent, gitlink, MRTS source, or
analyzer-configuration change is included.
