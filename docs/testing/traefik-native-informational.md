# Traefik native informational-response regression

**Language:** English | [Deutsch](traefik-native-informational.de.md)

The Framework owns the regression for external Connector finding
`SEC-TRAEFIK-NATIVE-001`. Product source remains in the Connector repository.
This suite checks that 100, 102 and 103 do not consume the final response's P3,
commit metadata or request-body EOS. Status 101 retains the existing terminal
Upgrade/Hijack contract.

The standard selection remains exactly 100 expanded cases. These additional
specialists require explicit `--on-demand` and `ON_DEMAND_TESTS=1`; the inventory
admits only the named selectors with reviewed source bindings. A source-only
or package-seam result does not establish a real Traefik/libmodsecurity result.

| Execution suffix after `specialist.sec-traefik-native-001.` | Expanded cases | Observable contract |
| --- | ---: | --- |
| `final-decision` | 13 | Real HTTP server/client; `httptrace.Got1xxResponse`; 100/102/103, repeated 1xx, final 200/201/401/403, final-only protected header, P3 allow/deny/redirect and controls, keepalive followup, one cleanup |
| `request-eos` | 3 | 1xx does not drain request bytes or run request EOS |
| `implicit-final` | 10 | Write, empty Write, Flush, ReadFrom and handler return preserve final P3 allow/deny |
| `streaming` | 1 | Client receives first bytes before upstream EOS; bounded P4 chunks and one EOS/cleanup |
| `upgrade` | 1 | 101 remains terminal; Hijack does not fabricate P4/EOS; one cleanup |
| `header-bounds` | 3 | Invalid name, header-count overflow and byte overflow fail before informational forwarding/P3 |
| `host` | 4 | Real pinned Traefik/plugin/private UDS/libmodsecurity: 103-deny, no-103 deny, 103-allow and legitimate followup |

The deny assertions distinguish protected upstream bytes from the middleware's
own `request rejected` response body. The Go tests use actual HTTP transport
for informational response semantics; the recorder is used only for state and
failure paths where no informational response reaches the host.

Set `CONNECTOR_ROOT`, the exact `CONNECTOR_REVISION`, `TEST_ROOT` to this
Framework checkout, and `CONNECTOR_TEST_OUTPUT_ROOT` to an owned external
directory. Keep Python/Go caches and temporary paths external too. Invoke the
Framework entrypoint through RTK, for example:

```sh
rtk bypass env ON_DEMAND_TESTS=1 "$PYTHON" -P -m modsecurity_test_framework.connector \
  --connector-root "$CONNECTOR_ROOT" --connector-revision "$CONNECTOR_REVISION" \
  --test-root "$TEST_ROOT" --output-root "$CONNECTOR_TEST_OUTPUT_ROOT" \
  --profile traefik-native --on-demand --strict-skips \
  --execution specialist.sec-traefik-native-001.final-decision
```

Use the other exact execution suffixes separately or repeat `--execution`.
For three independent real host repetitions select `host` in three separate
invocations and retain all output directories. The host adapter requires the
existing native runtime prerequisites and identity/isolation checks. A failed
prerequisite is a blocker; it is not permission to relax those checks.

The Go source overlay records selected source digests. Review the exact dirty
source delta together with the base revisions until commits exist. Framework
tests must be available before a Connector change updates its Framework pin;
merge and pin updates require separate authorization.
