# Change record

**Language:** English | [Deutsch](20261101-01-host-execution-context.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261101-01-host-execution-context |
| UTC date | 2026-11-01 |
| Framework base revision | d503ddbea1a3b6df7766edc247b0a9886ff10668 |
| Issue or pull request | Implementation-stage record; separate PR delivery and regular master integration authorized in the follow-up. Current delivery state is recorded by the repository PR. |

## Motivation and problem statement

Connector runtime preparation can see UID 0 inside a sandbox without the mappings or capabilities needed for a real root-master/worker transition. A prerequisite failure must be distinguished from connector behavior before starting the selected host runtime.

## Affected components and security boundaries

Framework-owned hostruntime preflight, bounded execution-context probes, NGINX smoke/lifecycle and Envoy start/runtime harness entry points. Parent connector implementation and promotion remain external dependencies. Protected broker namespace/trust contracts are unchanged. MRTS remains read-only; no Parent gitlink update is part of this Framework change.

## Acceptance criteria

Explicit profile requirements produce bounded per-check evidence; real child credentials govern worker file/UDS probes; missing mappings/capabilities produce an environment blocker; existing preflight evidence remains `runtime_status=NOT_RUN`. EN/DE guidance describes fresh-session use and approval boundaries. Runtime completion requires separately observed host evidence.

## Alternatives considered

Inferring authority from UID 0, using parent-process access checks for a worker, accepting missing paths as proven denial, silently downgrading root-master profiles and automatically escaping the sandbox would weaken the intended contract. The selected approach probes explicit requirements and stops when they are unavailable.

## Implementation decision

Extend the existing Framework CLI with context-only mode and explicit worker, root-master, chown, path and UDS requirements. Keep binary preflight and runtime claims separate. Bound child execution and metadata, reject untrusted paths, verify supplementary groups and remove only probe-created artifacts. Per-command host approval remains external to code; permanent service configuration is unchanged.

## Changed files and tests

Delivery review also requires zero new SonarQube Cloud issues and security hotspots at the final head. An earlier passing Quality Gate still reported seven new maintainability findings (four complex functions, a nested conditional and two nested context managers). The delivery follow-up separates worker resolution, path operations, child-report transport and requirement checks into bounded helpers and combines context managers while preserving identity, denial, timeout and cleanup behavior. It does not suppress findings or change analysis rules. Final server counts are verified through the current PR analysis.

`connector_suite/modsecurity_connector_ci/runtime/common/execution_context.py`, `hostruntime_preflight.py`, `connector_suite/modsecurity_connector_tests/test_execution_context_preflight.py`, NGINX smoke/lifecycle entry points and Envoy start/runtime harnesses. Tests cover child identity, writes, UDS, real worker transition when available, missing capabilities/mappings, symlinks, denial, existing sockets, timeout/reaping, an inherited daemon context launched through setpriv, and CLI evidence semantics. Source binding: `connector_suite/config/testing/active-cases.json` retains the same selectors/cases (100 active defaults), refreshes three changed harness digests through `update-inventory-bindings.py --apply`, and binds the two preflight modules to five affected executions. The daemon launcher fixture now retains evidence below its selected test root instead of a dated task directory. Documentation: `docs/host-execution-context.md` and its German companion, plus this paired record.

## Commands and results

The implementation-stage coordinator ran the explicit Framework interpreter through `rtk bypass env PYTHONPATH=<Framework>:<Framework>/connector_suite TEST_ROOT=<Framework> CONNECTOR_ROOT=<Parent> CONNECTOR_REVISION=a6001a09210bc9516256d28af5da45d73f0fe2f2 <Framework-interpreter> -P -m unittest -v`: the ten `test_execution_context_preflight` methods plus three selected existing binary-preflight regressions passed (13 tests; host context). Seven focused NGINX path/orchestration checks passed, including the gate that rejects context before projection/configtest/child start. Exact selectors/results are retained in `private/final-preflight-tests.log` and `private/final-integration-tests.log` under the task evidence root. Shell syntax (three scripts), Python AST (five changed modules), scoped Gitleaks (16 changed source files, no leaks), and both repository `git diff --check` checks passed. Framework `rtk make check-bilingual-docs check-doc-links check-change-records PYTHON=<Framework-interpreter> BUILD_ROOT=<task>/private/docs-checks TMP_ROOT=<task>/private/docs-checks/tmp LOG_ROOT=<task>/private/docs-checks/logs` passed. Parent V3.2 structure and touched context-digest checks passed; full inheritance retains unrelated baseline failures.

Delivery verification repeated all 13 preflight tests in the approved host context and all seven focused integration tests in a fresh external directory: both selections exited 0. `update-inventory-bindings.py --check` reports `INVENTORY_BINDINGS_VERIFIED`; helper binding updates preserve all previous source references and case/selector semantics. Delivery run: `20261101-context-delivery`. New private logs/evidence remain outside Git.

The Connector bilingual integration checker also exposed the German guide's language-switch order. The guide and paired record now place the English link before the German language label. The existing checker accepts the corrected guide; no checker or runtime logic was changed for this correction.

## Security impact

This change strengthens prerequisite and evidence classification; it is not a validated vulnerability remediation. It does not grant host privileges, alter protected broker trust or weaken private-path isolation. No secrets, raw payloads or environment dump are included.

## Documentation and runtime evidence

The paired guide is routed through Framework and Parent `.codex/context/index.md`. Task evidence: `<implementation-evidence-root>/private/verification.json`. The Parent-owned real NGINX `multiple_sequential_requests` invocation used the existing native sequence driver: configuration/readiness, HTTP 200/403/200, deny rule `1100001`, actual master UID/GID 0 and worker UID/GID 65534, then verified process/listener cleanup. The additional real `setpriv` launcher ran the current preflight source as daemon UID/GID 1 with empty supplementary groups and successful file/private-UDS probes. Its result retains `runtime_status=NOT_RUN`. All 150 retained relevant Parent product-source hashes match the reused NGINX build; historical build revisions differ from current HEAD, so this is source-hash-scoped runtime evidence, not an exact-head rebuild or broker attestation.

## Checks not run

No Envoy hosted runtime: no Envoy executable was available. Its hooks received source/syntax and shared UDS-boundary regression checks. Full lint/CI, full historical matrices, protected brokers and MRTS execution were not run. Ruff is unavailable in the Framework environment; no packages were installed. Parent/Framework inheritance validation still reports pre-existing unrelated stale digests/unregistered local policy; Framework configuration validation has a pre-existing missing `.codex/config.toml`. Touched Parent index/preflight digests were updated and independently checked without modifying MRTS pins.

## Limitations and residual risk

A profile label does not infer requirements. Fresh probes remain necessary for each actual launcher/session. Original historical process evidence is unavailable; the same one-identity namespace/capability blocker was reproduced now and compared with an approved host context. `systemd-detect-virt` reports KVM in both contexts and container isolation only in the command sandbox. UDS client probes use the actual pathname after pinning the server directory; preflight still cannot prove every connector binary's pathname-sensitive policy. Independent reviewers' traversal and separate-UDS-root findings were corrected and covered by focused tests; final read-only review found no remaining material finding.

## Final diff and review status

At the initial implementation handoff, scoped diffs and secret checks passed and the changes were uncommitted. The follow-up authorizes Framework PR delivery and exact-head regular master integration before a separate Connector pin PR. Current PR/head/CI/merge facts belong to repository PR metadata; historical local observations above are not current-head CI claims. MRTS remains unchanged and private runtime artifacts are excluded from delivery.
