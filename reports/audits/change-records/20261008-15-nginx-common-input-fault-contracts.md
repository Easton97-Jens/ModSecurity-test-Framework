# NGINX Common input-fault contracts

**Language:** English | [Deutsch](20261008-15-nginx-common-input-fault-contracts.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20261008-15-nginx-common-input-fault-contracts` |
| UTC date | 2026-10-08 |
| Framework base revision | `210a33c44c8620d42db7393524083294cf052cf5` |
| Issue or pull request | Framework PR #137 follow-up; not published |

## Motivation and problem statement

Two Required input faults need actual native Common validation, not driver-produced events.

## Affected components and security boundaries

New runner helper, focused controls and this bilingual record only; catalog/schema remain coordinator-owned.

## Acceptance criteria

Genuine own-worker/transaction/URI guard fault, mapper return0, HTTP400 and native phase1 protocol error without a rule; same-run/process cleanup and wrong-target controls.

## Alternatives considered

No fake phase2 completion or generic HTTP500 interpretation for the existing NGINX mapper boundary.

## Implementation decision

Declare closed NGINX-only phase1/400/mapping_error contracts while retaining generic catalog semantics elsewhere. Bind raw protocol error by actual transaction to native guard ledger and access observation.

## Changed files and tests

tests/runners/nginx_common_input_faults.py and tests/no_crs/test_nginx_common_input_faults.py; EN/DE records.

## Commands and results

Four focused unit tests passed after continuation hardening, including wrong transaction/process/run, guard return1 or boolean false, absent/duplicate/foreign native event, rule substitution, HTTP405 and boolean phase rejection. Framework-owned interpreter: `rtk proxy env PYTHONNOUSERSITE=1 PIP_REQUIRE_VIRTUALENV=true PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -m unittest tests.no_crs.test_nginx_common_input_faults -v`, exit0; the exact environment-owned interpreter path is retained in the external task handoff. Native `make test-no-crs-contract` with explicit Framework Python and external roots passed213 tests, exit0; the initial `make check-documentation` passed, exit0. Later documentation recheck rejected a local developer path in this record; the command example now uses a portable placeholder. All commands used RTK.

## Security impact

No Required shrinking, synthetic events, validator relaxation or MRTS changes.

## Documentation and runtime evidence

Old-cache diagnostic header focus returned actual400/Commonreturn0/native protocol_error and driver0; wrongTX driver1/405/noevent. Old bodyguard actually returned1/405 and remains RED until rebuilt product guard. Actual Common event_jsonl protocol view emits protocol_error, not phase1_error; exact validator and fresh header retry reflect that source contract. All raw records/maps/Root/nobody/cleanup remain external. Unit observations are never runtime records.

## Checks not run

Full integrated E2E, remote CI/Sonar and final canonical validation not run.

## Limitations and residual risk

The coordinator must register and independently revalidate closed raw artifact receipt mappings and real build identity. The pure observation helper does not authenticate receipt hashes or revisions. Roles and cleanup now bind the exact run and observed master/worker PIDs.

## Final diff and review status

Focused files only; separate local commit after bounded diagnostic focus; no push/gitlink/merge/PASS claim. Rebuilt body-positive and final exact-source validation remain required.
