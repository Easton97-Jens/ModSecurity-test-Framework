# Change record: explicit TLS protocol floor

**Language:** English | [Deutsch](20261102-02-tls-protocol-floor.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261102-02-tls-protocol-floor |
| UTC date | 2026-11-02 |
| Framework base revision | `f11d4617ff98ad615c72c1b6672fc386394db41e` |
| Issue or pull request | GitHub CodeQL alerts #17–#21; candidate PR not yet created at this record's draft stage |

## Motivation and problem statement

The five remaining open `py/insecure-protocol` findings concern SSL contexts without an explicit protocol minimum. Earlier tests of the actual host already rejected legacy TLS through platform defaults. This change establishes an explicit source contract; it does not assert that an exploitable legacy handshake existed on that host.

## Affected components and security boundaries

Two Framework-owned HAProxy harness client contexts and three loopback fixture server contexts form the boundary. Clients retain CA validation and hostname checks. Parent product source and Framework gitlink are unchanged; MRTS remains `default_read_only`. Earlier individual alert dispositions are untouched.

## Acceptance criteria

All five actual contexts explicitly require TLS 1.2, retain their unconstrained maximum and support TLS 1.2/1.3. Actual contexts must reject TLS 1.0/1.1 after permissive peers successfully negotiate those protocols as positive controls. Clients must reject a wrong hostname and an untrusted certificate. The standalone native client copy and existing real loopback/child-process controls must remain usable. Native metadata, documentation, security contracts, independent review and exact-head hosted checks must pass. Unchanged native CodeQL must omit the five affected results while preserving the other raw results. Master alert closure requires separately authorized integration and subsequent analysis.

## Alternatives considered

Relying on current OpenSSL defaults leaves the source contract implicit. Dismissal, suppression, exclusions or weakened queries do not implement the requested fix. A shared imported context module would break the native client's standalone source-copy contract. A TLS 1.2 maximum would unnecessarily disable TLS 1.3. Five small local context factories avoid those changes.

## Implementation decision

Extract each existing constructor into a local factory, set `context.minimum_version = ssl.TLSVersion.TLSv1_2`, and use that factory at the existing runtime call site. Certificate loading, CA validation, hostname checks, socket handling and strict EOF behavior remain intact. Do not set a maximum version or introduce an external import into the copied native client.

The regression uses real `ssl.MemoryBIO` peers and actual application bytes, with a bounded handshake loop. Deliberately permissive legacy peers exist only inside socket-free positive controls; actual subject contexts are never weakened. Unavailable legacy controls fail explicitly. Required CI execution treats every skip as blocked.

The selected [CodeQL SSL model](https://github.com/github/codeql/blob/6e9f9e38390175c41b99070a423c875f450759ca/python/ql/src/Security/CWE-327/Ssl.qll#L130) models this minimum-version assignment as a protocol restriction. This source-model evidence still requires exact-candidate scanner confirmation.

## Changed files and tests

- `connector_suite/adapters/haproxy/harness/i12_companion_host.py` and `i12_native_sequences.py`: explicit verified-client context factories used by the live paths.
- `connector_suite/modsecurity_connector_tests/test_envoy_transport_hardening_contract.py`, `test_haproxy_htx_transaction_id.py` and `test_haproxy_i12_companion_host.py`: explicit server context factories used by the existing fixtures. The companion child-process assertion obtains its expected script through the existing `source_path` selection contract rather than a stale Parent path.
- `tests/security_regression/test_tls_protocol_floor.py`: seven methods, 32 expanded scenarios: five source-floor checks, two legacy positive controls, ten legacy rejections, ten modern positives, four client-authentication negatives and one isolated standalone-copy check.
- `.github/workflows/ci-findings-regressions.yml`: include changed paths and run the new regression plus three existing actual loopback/child-process controls without accepting skips. Scanner queries, categories, exclusions and permissions are unchanged.
- Native generators refresh exactly three inventory source hashes, add seven archived definitions (7,966 to 7,973), and update migration source/caller metadata. All case IDs and selectors are unchanged: default 100 cases/80 executions, optional 2,586/1,140 and 1,993 original IDs preserved.

## Commands and results

All procedures use RTK and the Framework-owned interpreter. `FRAMEWORK_ROOT` denotes the task worktree; `RUN_ROOT` denotes the configured external evidence root for run ID `framework-tls-floor-20261102`. Exact invocation details and lifecycle results are retained in its execution plan; no raw logs or certificate private keys are copied here.

| Command or observed procedure | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused source-floor regression before adding the five assignments | Nonzero | Five subtest failures: `MINIMUM_SUPPORTED` differs from TLS 1.2; this proves the missing explicit property, not a negotiable legacy exploit | RUN_ROOT |
| Framework interpreter, `-m unittest discover -s tests/security_regression -p test_tls_protocol_floor.py -v`, with explicit Framework source context and external temporary root | 0 | Seven methods pass, zero skips; all 32 scenarios above pass | RUN_ROOT |
| Three explicit existing selectors: Envoy verified-loopback/root-confined evidence, HAProxy HTX verified-loopback certificate, companion actual harmless TLS client process | 0 | Three pass after the source-selected expected-argv correction | RUN_ROOT |
| Attempt to use local pytest | Nonzero | `No module named pytest`; no dependency installation performed | RUN_ROOT |
| Exact new workflow Python body, extracted from the checked-in YAML and run with the Framework interpreter | 0 | Ten methods pass, zero skips: seven new plus three actual controls | RUN_ROOT |
| Native `update-inventory-bindings.py --apply` / `--check`, `update-test-archive.py` / `--check`, `build-migration-map.py` / `--check` | 0 | All generation/freshness checks pass; counts and selectors above preserved | RUN_ROOT |
| Six-source `py_compile`, `actionlint .github/workflows/ci-findings-regressions.yml`, both native CI security contract scripts | 0 | Syntax, workflow lint and scanner/evidence contracts pass | RUN_ROOT |
| Fresh read-only candidate bypass/regression review | Completed | No concrete surviving bypass or introduced regression found | Current task |
| `rtk make check-documentation check-canonical-common-pins check-canonical-python-pins check-canonical-workflow-pins check-canonical-crs-contract-pins` with explicit Framework interpreter/build root | 0 | Documentation, paired record, paths/links and all four canonical pin checks pass | RUN_ROOT |
| Hosted CodeQL/CI/Sonar | Pending before commit | Exact candidate results must be observed; earlier revisions are not substituted | Current task |

## Security impact

The five original context paths now explicitly disallow protocol versions below TLS 1.2. The actual factories are tested against both legacy versions; permissive controls establish that failure is not merely unavailable platform protocol support. TLS 1.2/1.3 success and unchanged maximum cover modern compatibility. Wrong-hostname and alternate-authority certificates remain rejected by both clients. No production security level, authentication requirement or scanner control is reduced.

## Documentation and runtime evidence

This EN/DE record is the reader-facing documentation change. Evidence includes bounded real TLS negotiation in memory, actual verified loopback requests and a real child process; these are Framework component checks. They do not establish historical I12 qualification, connector promotion or a full connector campaign. Parent gitlink remains unchanged; MRTS stays read-only. No alert dismissal or master integration is performed.

## Checks not run

The full historical I12 campaign is outside this requested five-context change. The full older pytest module is not claimed passed because pytest is absent locally; source-specific unittest, protocol/copy and actual loopback/child-process controls supply selected local evidence. Exact-head hosted CI/CodeQL/Sonar remain pending before commit; final results belong in the PR and external lifecycle evidence.

## Limitations and residual risk

Local Python is 3.14.4; the CI pin is 3.14.8. Local tests do not replace exact-head hosted checks. A source-compatible CodeQL pattern alone does not prove disappearance: unmodified candidate SARIF must be compared under unchanged rules and scope. Branch evidence and master alert state remain separate; automatic `Fixed` status depends on a separately authorized merge and successful master scan. No exploitable legacy handshake or full runtime qualification is asserted.

## Final diff and review status

Source, test, workflow and generated changes are scoped to this correction. Independent review found no concrete bypass/regression; whitespace, documentation and canonical pin validation pass. Commit and hosted lifecycle remain for final reconciliation. This record contains no secrets, certificate private keys, credentials, raw request/response bodies or full logs.
