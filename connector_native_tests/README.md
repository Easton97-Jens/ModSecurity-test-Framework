# Connector native regression tests

This package owns native self-test definitions extracted from the Connector
product translation units. `extraction-manifest.json` records the original
function digests. Definitions and assertions were preserved during extraction.
The product binaries expose their service, configuration and metadata commands;
they no longer execute this test corpus through `--self-test`.

These are explicit specialist tests. They do not enlarge the automatic default
inventory, and a native self-test pass is not hosted connector runtime evidence.
The runner requires `ON_DEMAND_TESTS=1` or an inventory-admitted execution.

```sh
ON_DEMAND_TESTS=1 python connector_native_tests/run.py \
  --connector-root /absolute/Connector \
  --connector-revision FULL_40_CHARACTER_CONNECTOR_HEAD \
  --test-root /absolute/Framework/connector_native_tests \
  --profile native-selftest \
  --target envoy-bridge \
  --output-root /absolute/existing/external/output
```

| Target | Preserved checks |
| --- | --- |
| `envoy-bridge` | Allow, header deny and URI deny |
| `lighttpd-bridge` | Starter capability and non-promoting probe contract |
| `traefik-decision-service` | Allow, URI deny and header deny |
| `haproxy-spoa-starter` | Allow, local deny and invalid request |
| `traefik-engine` | Protocol parsing and private listener ownership |
| `haproxy-modsecurity-binding` | Native rule, request/body and lifecycle checks |
| `haproxy-spop-runtime` | SPOP framing, queue, failure, deadline and cleanup checks |

`traefik-engine` additionally requires `--socket-parent` naming an existing short
external parent. The runner allocates its own private child there.
`haproxy-modsecurity-binding` requires either
`--argument=--self-test --argument=/absolute/lifecycle-rules.conf` or
`--argument=--self-test-crs --argument=/absolute/crs-preamble.conf`.
Complex targets require a compatible native ModSecurity SDK/library; explicit
`--modsecurity-include` and `--modsecurity-lib` select existing installations.

The Framework creates a private external translation unit that includes the
explicit product source and Framework-owned definitions. This preserves access
to package-private C helpers without adding a Framework dependency to product
binaries. Compilation retains C17, `-Wall -Wextra -Werror` and pthread support.
Each invocation owns bounded compiler/test process groups and separate output.

`result.json` records both repository revisions, the profile, actual exit status,
whether the product checkout is dirty, and a digest of `input-bindings.json`.
The latter binds the actual product/test inputs and is rechecked after execution;
an input change fails the invocation. `--build-only` records compilation only.
Failed specialist tests remain failed and retain their diagnostics.
