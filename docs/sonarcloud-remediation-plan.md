# SonarCloud Remediation Plan

**Language:** English | [Deutsch](sonarcloud-remediation-plan.de.md)

Source: SonarCloud API for project
`Easton97-Jens_ModSecurity-test-Framework`, branch `master`, queried on 2026-05-15.
The query returned 31 open issues in the current remote analysis snapshot:
14 `shelldre:S131`, 8 `shelldre:S7679`, 6 `python:S3776`,
2 `python:S8495`, and 1 `shelldre:S1192`. The statuses below describe the
source-level remediation in this branch; SonarCloud will only close remote issue
keys after the next analysis run.

| Issue | Category | Severity | Affected file | Real issue or false positive | Fix strategy | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `AZ4tAdJg9wBRmoDDtssa` | shell robustness | critical | `ci/runtime/probe-response-body-blocking.sh` | real | Add default `case` branch for generated path guard | fixed |
| `AZ4tAdJg9wBRmoDDtssb` | shell robustness | critical | `ci/runtime/probe-response-body-blocking.sh` | real | Add default `case` branch for repeat validation | fixed |
| `AZ4s4GI2gYpe4Bv-weG2` | Python complexity | critical | `tests/runners/case_cli.py` | real | Replace conditional chain with capability-to-variable mapping | fixed |
| `AZ4ssKb2W4Q6haNCFVpJ` | Python complexity | critical | `tests/runners/case_cli.py` | real | Split summary loading/counting/metadata rendering into helpers | fixed |
| `AZ4si0gF6hf2ZRDnADZt` | Python complexity | critical | `tests/runners/runner_core.py` | real | Split case validation into metadata/request/response/expect helpers | fixed |
| `AZ4si0gF6hf2ZRDnADZu` | Python complexity | critical | `tests/runners/runner_core.py` | real | Split case discovery into path resolution and candidate selection helpers | fixed |
| `AZ4si0gF6hf2ZRDnADZv` | Python return consistency | major | `tests/runners/runner_core.py` | real | Return `list[str]` consistently from response assertions | fixed |
| `AZ4si0gF6hf2ZRDnADZw` | Python return consistency | major | `tests/runners/runner_core.py` | real | Return `list[str]` consistently from audit assertions | fixed |
| `AZ4si0gF6hf2ZRDnADZx` | Python complexity | critical | `tests/runners/runner_core.py` | real | Split audit waiting and field checks into helpers | fixed |
| `AZ4oLv83Rucw6R5zlwc_` | shell positional parameter | major | `ci/provisioning/prepare-nginx-build.sh` | real | Assign `$1` to `target_path` before use | fixed |
| `AZ4oLv83Rucw6R5zlwdA` | shell positional parameter | major | `ci/provisioning/prepare-nginx-build.sh` | real | Assign `$1` to `target_path` before use | fixed |
| `AZ4oLv83Rucw6R5zlwdB` | shell robustness | critical | `ci/provisioning/prepare-nginx-build.sh` | real | Add default `case` branch for generated path guard | fixed |
| `AZ4oLv83Rucw6R5zlwdC` | shell robustness | critical | `ci/provisioning/prepare-nginx-build.sh` | real | Add default `case` branch for refresh guard | fixed |
| `AZ4oLv83Rucw6R5zlwdD` | shell robustness | critical | `ci/provisioning/prepare-nginx-build.sh` | real | Add default `case` branch for GitHub repo URL parsing | fixed |
| `AZ4oLv_yRucw6R5zlwdE` | shell robustness | critical | `connectors/nginx/harness/run_nginx_smoke.sh` | real | Add default `case` branch for generated path guard | fixed |
| `AZ4oLv_yRucw6R5zlwdF` | shell positional parameter | major | `connectors/nginx/harness/run_nginx_smoke.sh` | real | Assign `$1` to `raw_value` in `escape_sed()` | fixed |
| `AZ4oEgW0zQbBYyxTDd5x` | Python complexity | critical | `tests/runners/runner_core.py` | real | Move fallback YAML parsing into `MinimalYamlParser` helpers | fixed |
| `AZ4n9oXR_9oVCvgyS3Qi` | shell robustness | critical | `connectors/apache/harness/run_apache_smoke.sh` | real | Add default `case` branch for generated path guard | fixed |
| `AZ4n9oXR_9oVCvgyS3Qk` | duplicated literal | minor | `connectors/apache/harness/run_apache_smoke.sh` | real | Introduce `IFMODULE_END` constant | fixed |
| `AZ4n9oXR_9oVCvgyS3Qj` | shell positional parameter | major | `connectors/apache/harness/run_apache_smoke.sh` | real | Assign `$1` to `raw_value` in `escape_sed()` | fixed |
| `AZ4n9oVN_9oVCvgyS3Qe` | shell positional parameter | major | `ci/provisioning/prepare-apache-build.sh` | real | Assign `$1` to `target_path` before use | fixed |
| `AZ4n9oVN_9oVCvgyS3Qf` | shell positional parameter | major | `ci/provisioning/prepare-apache-build.sh` | real | Assign `$1` to `target_path` before use | fixed |
| `AZ4n9oVN_9oVCvgyS3Qg` | shell robustness | critical | `ci/provisioning/prepare-apache-build.sh` | real | Add default `case` branch for generated path guard | fixed |
| `AZ4n9oVN_9oVCvgyS3Qh` | shell robustness | critical | `ci/provisioning/prepare-apache-build.sh` | real | Add default `case` branch for refresh guard | fixed |
| `AZ4n6KQK9eBhNcyBKSiZ` | shell robustness | critical | `ci/runtime/run-v3-api-smoke.sh` | real | Add default `case` branch for `BUILD_ROOT` guard | fixed |
| `AZ4n6KQK9eBhNcyBKSia` | shell robustness | critical | `ci/runtime/run-v3-api-smoke.sh` | real | Add default `case` branch for `BUILD_DIR` guard | fixed |
| `AZ4n6KOS9eBhNcyBKSiU` | shell positional parameter | major | `ci/provisioning/build-v3-under-src.sh` | real | Assign `$1` to `target_path` before use | fixed |
| `AZ4n6KOS9eBhNcyBKSiV` | shell positional parameter | major | `ci/provisioning/build-v3-under-src.sh` | real | Assign `$1` to `target_path` before use | fixed |
| `AZ4n6KOS9eBhNcyBKSiW` | shell robustness | critical | `ci/provisioning/build-v3-under-src.sh` | real | Add default `case` branch for generated path guard | fixed |
| `AZ4n6KOS9eBhNcyBKSiX` | shell robustness | critical | `ci/provisioning/build-v3-under-src.sh` | real | Add default `case` branch for destination guard | fixed |
| `AZ4n6KOS9eBhNcyBKSiY` | shell robustness | critical | `ci/provisioning/build-v3-under-src.sh` | real | Add default `case` branch for refresh guard | fixed |

## Follow-Up Cleanup

The following additional SonarCloud code smells were reported after the first
remediation pass and are fixed in source without suppressions:

| Issue | Category | Severity | Affected file | Real issue or false positive | Fix strategy | Status |
| --- | --- | --- | --- | --- | --- | --- |
| screenshot L43 | Python code smell | minor | `ci/reporting/write-case-matrix.py` | real | Remove the unused `path` parameter from `case_kind()` | fixed |
| screenshot L45 | Python code smell | minor | `ci/reporting/write-case-matrix.py` | real | Replace chained `startswith()` calls with a tuple argument | fixed |
| screenshot L17 | regex cleanup | minor | `tests/normalizers/audit_log_normalizer.py` | real | Remove the redundant lowercase range from an `IGNORECASE` character class | fixed |
| screenshot L12 | regex cleanup | minor | `tests/normalizers/response_normalizer.py` | real | Remove the redundant lowercase range from an `IGNORECASE` character class | fixed |
| screenshot L159 | Python code smell | minor | `tests/runners/case_cli.py` | real | Use `dict.fromkeys()` for stable duplicate removal in verified variables | fixed |

Split status: `tests/runners/case_cli.py` in this repository already contains
the `dict.fromkeys()` duplicate-removal fix. No suppression is used.

No issue is intentionally suppressed. If SonarCloud reports follow-up issues or
keeps any of these keys open after the next analysis, update this table with the
new evidence and fix strategy instead of hiding the warning.
