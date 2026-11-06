# Protocol acceptance preparation change record

**Language:** English | [Deutsch](20261106-01-protocol-acceptance-preparation.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261106-01-protocol-acceptance-preparation |
| UTC date | 2026-11-06 |
| Framework follow-up base revision | `b5d8d9442d7751c04ee84f478f594fc84a236e3b` |
| Issue or pull request | [Framework PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169); final delivery identities and CI receipts remain external |

## Motivation and problem statement

Prepare real modern-protocol qualification without changing the 100 standard
cases or existing assertions. The original NGINX preparation run found four
required H2 reset failures. This follow-up proves and fixes that dependency
cause, strengthens client/evidence controls, and adds separate Apache, local
HTX, SPOP/HTX-companion and Envoy H2 preparation paths. Comprehensive acceptance
remains **NOT_RUN**; global preparation readiness is not declared.

## Affected components and security boundaries

Framework owns opt-in registries, runners, clients, rules, readers, provisioning
helpers, tests, compile inventory and paired documentation. External Parent
dependencies own connector product changes, profile metadata and gitlink
delivery. MRTS remains read-only. Native test observers add lifecycle metadata
to private verified source copies; they do not replace cleanup or decisions.
Artifacts and evidence remain bounded, source-bound and external to the checkout.

## Acceptance criteria

Preserve all 25 NGINX IDs and the standard 100-case selection; register 32
additional IDs as eight scenarios for each of four distinct H2 profiles. Require
actual TLS/ALPN or explicit h2c, independent native/wire identity, real P2 POST
bodies, phase/rule correlation, first bytes before EOS, isolated termination,
healthy peer/follow-up and target cleanup before peer release or physical
connection close. Reject missing, contradictory, stale or corrupted evidence
and writer failures. Final committed-pair reruns and current-head CI remain
separate completion requirements.

## Alternatives considered

Timeout increases, weakened reset expectations, unsupported relabeling and
mock-only qualification would hide required behavior. Extending the default
inventory would change its contract. Separate opt-in adapters preserve existing
selection and expose each native profile's observable lifecycle.

## Implementation decision

An independent TLS/ALPN raw-frame experiment separated server flushing from
client processing. With a held peer, unpatched NGINX delayed RST about 12 seconds;
a PING after one second released it immediately. Native source showed queued
RST output with no write event when another stream remained active. The small
versioned NGINX patch posts that connection write event on the affected return
path. The native preparer applies it with zero fuzz after archive verification
and binds patch bytes into provenance/cache identity for H2 and H3 builds.

The NGINX libcurl client retains checked TLS 1.3 minimum, peer/host verification
and CA setup. Loopback h2c is explicit. Callback ABI and numeric JSON fields
remain typed. New non-NGINX adapters use a verified TLS 1.3 raw H2 frame client
with HPACK status decoding and an actual bounded P2 POST. Native cleanup,
Common engine decisions, actual host actions and wire outcomes remain distinct.
Native manifests admit the closed product input map, exact observer transform,
verified archive bytes, library and binary. Reuse requires fresh byte admission.

External Parent product fixes include Envoy's native Strict late response path
and profile policy. SPOP request phases and the HTX response companion keep
separate ownership witnesses; an early SPOP deny must not invent an HTX claim.
Empty SPOP test requests use explicit `Content-Length: 0`, documenting the
current NOTIFY ABI boundary rather than proving every H2 body framing.

## Changed files and tests

- NGINX lifecycle runner, protocol acceptance contract/client/rules and negative
  controls under `connector_suite/` and `tests/`.
- `ci/provisioning/patches/nginx/h2-close-stream-flush.patch`, native NGINX build
  helper and source/cache admission in runtime provisioning.
- `tests/runners/native_h2_probe.py` and `non_nginx_h2_acceptance.py`; separate
  Apache, HAProxy HTX, HAProxy SPOP/HTX and Envoy harnesses and focused tests.
- Apache and HAProxy native observer build helpers and verified source admission.
- CFamily compile recipes/inventory and native generated archive projections;
  the standard case selection and offline exception contract remain preserved.
- The paired [protocol guide](../../../docs/protocol-acceptance-preparation.md)
  and this record. Parent product/docs changes are external dependencies.

## Commands and results

`F` denotes the selected Framework checkout, `P` its explicit Parent checkout,
and `PYTHON` the existing Framework-owned Python 3.15.2 interpreter. All shell
commands use RTK. Exact commands, environment, source hashes, private paths,
preflight and raw results remain in the external follow-up evidence. No toolchain
installation was performed for the configured Python-version mismatch.

| Command or procedure | Result | External evidence |
| --- | --- | --- |
| Four unchanged NGINX H2 regression cases, before patch | 4 FAIL; native abort immediate, reset delayed until held-peer timeout | `h2/baseline-and-diagnosis.json` |
| Independent raw TLS H2 frame experiment, with/without PING | Delayed unpatched RST; PING triggers queued output; patched no-PING RST about 0.015 seconds with healthy peer/follow-up | `h2/diagnosis.md` |
| Native fresh patched NGINX H2 and H3 builds | PASS; exact source/archive/patch identity retained | `h2/targeted-before-after.json` |
| Same four H2 regression cases after patch | 4 PASS; all original reset/isolation assertions retained | `h2/targeted-before-after.json` |
| Eight existing H2/H3 adjacent host cases | 8 PASS on fresh H3-capable build; owned cleanup verified | `h2/targeted-before-after.json` |
| NGINX patch/archive focused checks | 25 PASS | `h2/unit-validation.json` |
| Real client TLS-1.2-only negative handshakes and CLI/debug controls | 3 handshake rejections, 28 controls PASS | `validation/client-current/` |
| Strict C17 callback ABI positive and const-negative compilation | Canonical callback types pass; two incompatible canonical assignments reject | `validation/abi-controls/` |
| Local native HTX H2, eight scenarios | 8 PASS, 24 transactions, 8 cleanup barriers while peer/TLS remain active | `profiles/haproxy/verification-receipt.json` |
| `rtk bypass env ... "$PYTHON" -P -m unittest connector_suite.modsecurity_connector_tests.test_haproxy_h2_acceptance -v` | 15 PASS; archive, observer, reader and artifact-admission controls | `profiles/haproxy/unit-final.log` |
| HTX real-bundle corruptions, artifact negatives and actual wire-writer failure | 100 controls PASS; real writer failure remains FAIL with verified cleanup | `profiles/haproxy/focused-controls.json` |
| Native Envoy H2 candidate | 8 PASS, 24 transactions, 8 live-peer cleanup barriers | `profiles/envoy/candidate-verification-hardened.json` |
| SPOP/HTX v4 final candidate | 8 PASS, 24 transactions, 8 live-peer cleanup barriers; owner EOS rule joined by unique handle/lease | `profiles/spop/candidate-verification-hardened.json` |
| Apache source/cache/provisioning contracts | 190 PASS, 5 dirty-checkout skips; fresh HTTPD/module build PASS; new H2 module correction under verification | `apache/final-apache-contracts` |
| `rtk bypass make check-documentation PYTHON="$PYTHON"` and scoped `rtk bypass git diff --check` | Exit 0; links, bilingual variables, repository paths, Change Record contract and whitespace pass | `profiles/haproxy/change-record-documentation.log` |

An intermediate SPOP/HTX v4 candidate had six passing and two failing scenarios.
The final candidate resolves the owner-specific EOS/handoff observation gap
through a copied-source diagnostic observer; Common product source is unchanged.
Apache's first actual H2 selection passed six scenarios and retained Strict/
upstream-reset failures. Independent no-PING/PING frames show missing abort
notification, unlike NGINX queueing; Parent owns the H2 error-bucket correction.
Local CRS preflight is blocked by the existing fixture's unmapped default worker;
current-pair hosted CRS and aggregate remain required.

Independent review withdrew the earlier Envoy cancellation qualification: its
upstream release allowed ordinary EOS. The hardened driver holds EOS through
native cancellation cleanup. Both readers now reject contradictory TLS/ALPN,
missing request/body/barrier evidence, wrong-phase/duplicate decisions and wrong
reset codes. SPOP wire-writer failure cannot bypass owned cleanup. Nineteen
focused tests, fresh eight-case runs for each profile and the actual writer-
failure cleanup control pass; bounded independent second review closes these
pointed gaps. Original receipts and the explicit qualification erratum remain.
Candidate observations do not replace final-pair runs.

## Security impact

The NGINX dependency fix restores timely request-local reset delivery without
weakening isolation or changing required errors. Native provenance rejects stale
or foreign source/artifacts. Client TLS setup fails closed; TLS-1.2-only controls
exercise actual rejection. No authentication, compiler warning, assertion,
capability or analysis gate is relaxed. No Sonar suppression or server issue
disposition is applied. Evidence excludes credentials, private keys and raw
response handles; SPOP/HTX correlation uses hashed handles.

## Documentation and runtime evidence

The EN/DE guide and record describe the separate 25/32 registries, commands,
observable boundaries and retained candidate evidence. Earlier sealed runs
remain historical: the original committed pair had 21/25 new NGINX cases pass,
four H2 failures and eight adjacent passes. The follow-up's independent causal
experiment and unchanged targeted reruns close that specific dependency defect.
Historical and candidate evidence are not relabeled as final committed-head
qualification. Absolute local paths and full source/artifact identities remain
in external receipts.

The six open Sonar occurrences and 30 analysis-closed occurrences receive an
individual factual review in external `sonar/per-occurrence-review.json` and
its Markdown companion. Canonical ABI compilation and actual TLS controls
support the technical review; they do not apply server `FALSE_POSITIVE` status
or establish a passing current Quality Gate.

## Checks not run

Comprehensive acceptance: **NOT_RUN**, explicitly deferred. Local Sonar scan,
installation, service startup and login: not performed. Final committed-pair
25+8 NGINX repetition, complete final non-NGINX qualification, Apache native
host/CRS evidence and authoritative current-head GitHub/Sonar/CodeQL outcomes
remain pending. No merge is authorized or performed by this preparation work.

## Limitations and residual risk

Candidate passes apply only to admitted source bytes/artifacts and selected
profiles. Apache completion remains open. The SPOP MRC1 boundary does not carry
the response rule ID or a distinct Strict outcome; an independent owner-side
observer joins that decision to handle/lease, native host action and wire.
All ten logical profiles retain separate capability claims; stock/patched
lighttpd keep their existing H1 contract. No global readiness or capability
promotion follows from build, registry, unit or candidate host evidence.

## Final diff and review status

The existing Framework [PR #169](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/169)
and external Parent [PR #445](https://github.com/Easton97-Jens/ModSecurity-conector/pull/445)
remain separate delivery boundaries. The explicitly authorized original pushes
and draft PRs do not imply a merge. This record replaces the stale incremental
appendices with the follow-up scope. Final source freeze, generator checks,
review, committed-pair qualification and exact-head CI receipts remain required;
their outcomes must be recorded before declaring preparation complete.
