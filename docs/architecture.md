# Architecture

**Language:** English | [Deutsch](architecture.de.md)

The Framework is a reusable test, normalization, and evidence layer for
ModSecurity connector projects. It is not a server, proxy, or connector
implementation.

## Repository boundary

| Layer | Responsibility |
|---|---|
| Framework | YAML cases, runners, normalizers, catalog checks, report generators, and bounded evidence validation |
| Common connector code | Connector-neutral data shapes only, where the connector repository provides them |
| Host adapter | Host hooks, filters, plugins, directives, configuration merge, and intervention translation |
| Connector evidence | Capability declaration, observed artifacts, and promotion decision |

Shared Framework code must not own host SDK objects, server configuration, or
unreviewed payload data. A connector adapter translates its host state into the
selected test and evidence contracts, then translates observed results back
into host-specific behavior.

## Native repository architecture contract

The strict [repository architecture model](../connector_suite/config/testing/repository-architecture.json)
defines three mandatory dependency rules from this document and the selected
Connector's versioned architecture and test-ownership contracts:

- Common C-family sources must keep host SDK includes in adapters. Local Common
  includes are resolved recursively; missing local and nonliteral include operands
  fail. Known Apache, NGINX, HAProxy, Envoy, lighttpd and Traefik SDK header
  signatures are rejected. External standard-library and `modsecurity/` engine
  headers remain valid and are not traversed as local sources.
- Product sources, libraries and production launchers must not depend on
  Framework test infrastructure. The checker inspects literal C-family
  include/load operands, Python imports and selected literal loading calls, Go
  imports and selected loading/linker operands, direct shell commands, and native
  build inputs. Make source/link variables, include directives, prerequisites and
  known compile/link commands are checked separately from pure test delegation.
  Framework test runners, harness/smoke/check entrypoints, lock/rule data inputs,
  thin Parent test delegation and explicitly bound Framework product-source
  readers remain valid. A data-looking suffix cannot exempt a known linker or
  compiler input.
- The Framework must not introduce a Parent gitlink. The explicit Framework root
  must be its Git top-level. Canonical Parent repository URLs and local/file URLs
  to the selected Product repository, including alternate worktrees of the same
  Git repository, are checked without fetching remote repositories.

The selected source scope is `common/` and `connectors/`: C/C++ headers and
sources, Python, Go, shell, shebang-bearing `.in` templates, `.mk`, `.m4`,
`go.mod`, Makefiles, `Makefile.am`, `configure.ac`, NGINX `config`, CMake, meson
and BUILD files. This is a bounded literal check, not a compiler, POSIX shell or
Make evaluator. Computed commands/imports, arbitrary remote repository aliases,
complete transitive language graphs, binary contents and object lifetimes need
separate review and native build/runtime evidence. Harmless explanation and log
strings do not constitute a dependency in the supported language forms.

The Parent's `check-repository-architecture` target is included in its delegated
lint. The direct check requires explicit roots:

```sh
"$PYTHON" "$FRAMEWORK_ROOT/connector_suite/modsecurity_connector_ci/checks/common/check-repository-architecture.py" \
  --connector-root "$CONNECTOR_ROOT" --framework-root "$FRAMEWORK_ROOT"
```

Exit `0` means `PASS`, `1` means a detected contract violation and `2` means an
invalid or incomplete check. Missing/empty models and required source scopes
cannot pass. The explicit on-demand `test_repository_architecture.py` module
exercises accepted inputs and deliberate violations without adding standard
Connector cases. This native check does not activate a Sonar architecture sensor
or claim that an inactive boundary check ran.

Migration provenance separately distinguishes original Product sources from
explicitly registered later Framework introductions. A registered introduction
must match its source-map route, Git introduction commit/blob, Framework ancestry
and absence from both immutable Product baselines. Current sources must be
regular, stay within the Framework root and have no symlink ancestors. Unknown
missing historical sources and Git errors remain failures; registration does not
turn them into later additions.

## Transaction and lifecycle model

The Framework represents a transaction through case metadata and bounded
artifacts. The host adapter owns the actual ordering and must report only
observed phases.

| Lifecycle area | Framework concern | Connector responsibility |
|---|---|---|
| P1 request start | Case selection and request metadata | Connection, URI, and request-header delivery |
| P2 request body | Body fixture and bounded assertions | Incremental body delivery, limits, and intervention behavior |
| P3 response headers | Response-header fixture and assertions | Header delivery and host response handling |
| P4 response body and logging | Non-promotion and privacy boundaries | Streaming, late intervention, final logging, and host-safe behavior |

P1–P4 names do not turn a declared phase into an implementation claim. In
particular, a Phase-4 log, pass-through response, or post-commit connection
outcome must follow the configured evidence policy and must not be presented as
pre-commit response-body blocking.

## Engine and host separation

libmodsecurity public APIs, rules, and transaction state belong to the engine
side. The host adapter controls when those APIs are called and whether a host
can safely apply an intervention. Connector-specific configuration, body
limits, content-type handling, logging, and connection behavior cannot be
generalized merely because the Framework uses common YAML.

The connector-free v3 API smoke is a bounded engine probe. It is not Apache,
NGINX, HAProxy, Envoy, Traefik, or lighttpd runtime evidence.

Its multipart line-break regression covers byte-exact `A\\r\\nB` and `A\\nB`
form values plus an `AB` allow control through the public C API.  A matching
engine intervention is not evidence that a connector delivered a backend or
client-visible effect, so these cases remain non-promoted until controlled host
evidence is available.

The public C API smoke also contains an exact AB representation control: an AB
form value must produce the configured phase-2 deny intervention, rather than
merely avoid the line-break rule.

## Capability and status model

Capabilities label exercised behavior; they do not automatically skip,
promote, or certify a case. Result status distinguishes observed PASS and FAIL
from BLOCKED, NOT_EXECUTABLE, mapped-only, pending, future, connector-gap, and
runtime-difference states.

`RESPONSE_BODY` remains non-verified and non-promoted until the applicable
connector evidence contract accepts stable proof. First-byte timing,
no-full-response-buffering, body limits, event privacy, and evidence promotion
are likewise validated from explicit artifacts rather than inferred from a
report or an exit status.

## Data, events, and privacy

Canonical result and event inputs use bounded, normalized metadata. They may
contain reviewed identifiers, phase, action or decision, status, HTTP status,
version, size, hash, truncation, and redaction facts allowed by the schema.
They must not contain raw request or response bodies, credentials, or
unreviewed host logs.

Hash-chain data can support smoke-level tamper detection. It does not provide
durable integrity without connector-owned secure key handling and storage.

## Build and cache boundary

Source copies, build outputs, logs, temporary data, and evidence live outside
the Git worktree under explicit paths. The Framework does not silently reuse a
parent workspace or rewrite source checkouts. Cache reuse never replaces
current configuration, start, runtime, or evidence validation.

## Related documents

- [Catalog and cases](catalog-and-cases.md)
- [Testing and evidence](testing-and-evidence.md)
- [Connector integration](connector-integration.md)
- [Development](development.md)
- [Variables and placeholders](reference/variables.md)
