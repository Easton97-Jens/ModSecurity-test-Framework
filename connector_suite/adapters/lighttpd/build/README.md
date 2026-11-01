# Stock-sidecar test artifacts

[Deutsch](README.de.md)

The Connector builds the product sidecar and its closed schema-2 `stock-sidecar-artifact.manifest`. It does not build or distribute the runtime-begin smoke.

Build that selected test through the Framework, with `ON_DEMAND_TESTS=1`, explicit `TEST_ROOT`, `CONNECTOR_ROOT`, `CONNECTOR_REVISION`, `CONNECTOR_TEST_PROFILE`, and absolute `MODSECURITY_INCLUDE_DIR` / `MODSECURITY_LIB_DIR`:

```sh
python -P -m connector_suite.adapters.lighttpd.build.build_runtime_begin_smoke \
  --sidecar-binary /external/product/lighttpd-stock-sidecar \
  --output-root /external/private-test-output
```

Use the Framework interpreter and its source-only `PYTHONPATH` (`TEST_ROOT:TEST_ROOT/connector_suite`), with `PYTHONSAFEPATH=1` and `PYTHONNOUSERSITE=1`. The output root must already exist outside both checkouts and be private to the invoking user.

The command prints a separate test-manifest path. Pass it as `STOCK_SIDECAR_TEST_MANIFEST` to the real-backend harness or sidecar loopback tests. This manifest binds the Framework revision, smoke source and binary hashes, and product-manifest digest. Compilation also checks that current product inputs and the ModSecurity library match the product receipt and remain unchanged during compilation. The real-backend harness verifies both manifests and still requires the independent operator artifact attestation.

A test build is not Stock-lighttpd host evidence. Rebuild both manifests after changing the recorded revisions or product sources; old schema-1 product manifests are rejected.
