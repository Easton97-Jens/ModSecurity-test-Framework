# Connector integration

**Language:** English | [Deutsch](connector-integration.de.md)

The Framework supplies reusable cases, runners, normalizers, catalog checks,
and report generation. A connector repository owns its host adapter, build
integration, runtime configuration, executable harness, and canonical
host evidence.

## Ownership boundary

| Area | Owner |
|---|---|
| YAML case schema, selection, and normalization | Framework |
| Host hooks, filters, plugins, and directives | Connector repository |
| Host build and runtime configuration | Connector repository |
| Connector capabilities and integration mode | Connector repository |
| Canonical runtime artifacts and promotion decision | Connector repository |
| Generated cross-case view | Framework generator consuming declared inputs |

The Framework may report `BLOCKED` when a required connector-owned harness is
absent. A Framework starter or self-test PASS never proves a host lifecycle.

## Adapter contract

An adapter must make its boundary explicit rather than exposing host objects to
shared code. The normal runner model covers preparation, startup, shutdown,
reload, configuration and rule application, endpoint discovery, request
execution, artifact collection, and cleanup. A connector may implement an
equivalent host-specific shape, but it must preserve the evidence boundary:
only observed behavior becomes runtime evidence.

Host-specific phase order, request and response body delivery, interventions,
logging, connection handling, and configuration merge rules remain
connector-owned. The Framework does not convert a declared capability into an
implementation claim.

## Maintained provenance

The following source facts are intentionally retained here because adapter
metadata drift checks validate them.

| Component | Upstream | Reviewed ref | Commit | Version | License | Adapter-owned path |
|---|---|---|---|---|---|---|
| ModSecurity-apache | https://github.com/owasp-modsecurity/ModSecurity-apache | master | `0488c77f69669584324b70460614a382224b4883` | `v0.0.9-beta1-26-g0488c77` | Apache-2.0 | `connectors/apache` |
| ModSecurity-nginx | https://github.com/owasp-modsecurity/ModSecurity-nginx | master | `9eb44fd9ab0988756e1ab8ce5aa5548ddbe57846` | `v1.0.4-14-g9eb44fd` | Apache-2.0 | `connectors/nginx` |
| ModSecurity v3 | https://github.com/owasp-modsecurity/ModSecurity | `v3.0.15` metadata; commit-only fetch | `0fb4aff98b4980cf6426697d5605c424e3d5bb60` | `v3.0.15` | Apache-2.0 | configured engine source |
| ModSecurity v2 | https://github.com/owasp-modsecurity/ModSecurity | v2/master | `02eed22d74667b32091eece088a8ebdf64b6ba67` | `v2.9.13` | Apache-2.0 | historical semantics reference |

Apache and NGINX productive adapter sources are deliberately
connector-specific. Their attribution, license, origin, and source maps also
remain in the connector repository. The Framework validates documentation
metadata without linking to connector C code.

ModSecurity v3 acquisition accepts only the literal OWASP HTTPS origin and
the reviewed full commit above. `v3.0.15` is release metadata rather than a
Git selector: empty legacy `MODSECURITY_*` aliases normalize to the reviewed
identity, while a non-empty differing value fails before Git use. The fetch
path always creates a fresh checkout; a
build path accepts an existing checkout only after it verifies that exact
origin and `HEAD` and rejects `.gitmodules` manifests and Gitlinks. No V3
submodules are initialized by the Framework.

## Six-connector boundary

| Connector | Framework role | Required evidence source |
|---|---|---|
| Apache | Select and materialize applicable cases | Connector-owned Apache host harness and artifacts |
| NGINX | Select and materialize applicable cases | Connector-owned NGINX host harness and artifacts |
| HAProxy | Select and normalize applicable cases | Connector-owned selected integration-mode harness and artifacts |
| Envoy | Select and normalize applicable cases | Connector-owned selected integration-mode harness and artifacts |
| Traefik | Select and normalize applicable cases | Connector-owned selected integration-mode harness and artifacts |
| lighttpd | Select and normalize applicable cases | Connector-owned selected integration-mode harness and artifacts |

The selected integration mode, capability manifest, configuration reference,
and lifecycle result belong to the connector repository. This avoids treating
documentation-only, compatibility, or prototype material as a native runtime
implementation.

## Compatibility paths

Historical HAProxy SPOE/SPOA discovery, disabled-key, report-schema, and
readiness notes described a possible compatibility direction only. They did
not implement a Framework connector key or prove a host runtime. Current work
must use the connector repository's declared integration mode and canonical
evidence; no historical planning text creates a capability or promotion.

The same rule applies to imported Apache, NGINX, v2, v3, and MRTS references:
their code or tests are inputs for review and derivation, not executable proof
in another connector.

## Updating an integration

1. Keep adapter metadata and connector origin records aligned with the
   adapter-owned source.
2. Declare the integration mode and capability boundary in the connector
   repository.
3. Provide a real host harness before claiming runtime support.
4. Normalize bounded artifacts and validate them through the applicable
   evidence contract.
5. Regenerate Framework reports only after their input evidence is current.

## Historical context

Separate import analyses, connector plans, and HAProxy SPOE/SPOA documents were
consolidated here. Git preserves the detailed migration history; this document
preserves the current ownership and attribution contract.
