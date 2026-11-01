# Composite lifecycle evidence verifier

**Language:** English | [Deutsch](README.de.md)

`verify_matrix_evidence.py` verifies one isolated lifecycle case using the raw JSONL
observer output emitted by the composite coordinator. It does not transform or
synthesize events and never correlates cases by request ID, URI, address,
arrival order, or timing.

Its success status is deliberately `LIFECYCLE_ONLY`, never `PASS`: the
case-driver, manifest, observations, and raw-log file live in one trusted
operator boundary. The verifier can therefore validate bounded metadata and
lifecycle consistency, but it cannot prove a rule/vector executed, a real host
loaded a template, or a client observed a host reset/abort. The JSON output
sets `"scope": "lifecycle_only"` and `"catalog_acceptance": false`.

```text
python3 connectors/composite_harness/verify_matrix_evidence.py CASE.manifest.json --json
# Runner-pinned invocation:
python3 connectors/composite_harness/verify_matrix_evidence.py CASE.manifest.json \
  --expected-event-log /absolute/path/case-001.events.jsonl --json
```

The manifest and its event log are sibling regular, non-symlink files. Each
manifest is one isolated case artifact:

```json
{
  "schema": "msc-composite-evidence/v1",
  "connector": "envoy",
  "case": "p4_safe",
  "case_artifact": {"id": "case-001", "event_log": "case-001.events.jsonl"},
  "expected_phases": ["P1", "P2", "P3", "P4"],
  "client_observation": "client.observation.json",
  "upstream_observation": "upstream.observation.json",
  "cleanup": {"count": 1, "status": "completed"}
}
```

The two observation files are separately captured, sibling regular
non-symlink files. The client file schema is exactly
`lease_observed`, `visible_status`, `redirect_location_verified`, `p4_outcome`,
`p4_visible_status`, and `p4_response_committed`; the upstream file schema is exactly
`lease_observed`, `request_terminal`, and `response_observed`. Each file is
bounded, duplicate-key rejecting, and metadata-only. The manifest only
references their basenames; inline observation assertions are invalid.

The event log is the unmodified raw observer JSONL. Its allowed record fields
are exactly `decision_id`, `connector`, `rule_id`, `phase`, `outcome`, `reason`,
`requested_action`, `actual_host_action`, `visible_status`,
`cleanup_outcome`, `event_time`, `request_path`, `response_path`, and
`transport`; optional fields may be omitted exactly as the Go observer emits
them. `request_path`, `response_path`, and `transport` bind every record to the
connector's static pipeline. `phase` accepts the required P1--P4 records and
the lifecycle records `reservation`, `lease`, `claim`, `request_host_action`,
`host_action`, `neutral_outcome`, and `terminal`. Every record must have the same connector
and exactly one server-generated decision ID must occur in the isolated log.
The verifier requires the case's P1--P4 records once and in order, plus one
final `terminal` record whose `cleanup_outcome` is `closed`. Lifecycle records
may occur between the required phase records; they are never used to join
cases.

The command writer limits each JSONL record to 2,048 bytes, retains a normal
1 MiB window, and defers a reset until the active decision lifecycles are
complete. During bounded concurrent activity it permits a fixed 8 MiB hard
ceiling; if that ceiling cannot preserve a complete lifecycle, the observer
fails closed. A failed or no-progress partial write is rolled back. At startup
it removes only a malformed trailing JSONL sequence and, before any later
rotation, appends a `terminal` record with `reason` and `cleanup_outcome`
`restart_recovery` for each schema-valid open lifecycle left by a crash. Each
active lifecycle reserves one maximum-sized terminal line. If a prior
owner-only, pre-reservation log at or below the hard ceiling lacks that recovery
space, startup safely resets the unrecoverable old window because a restarted
coordinator cannot resume its transactions; current writes instead fail closed
before consuming their terminal reservation. Files above the hard ceiling also
reset. A long-running service therefore does not retain every historical
lifecycle; each verifier case uses a fresh isolated log and remains far below
the retention threshold.

The referenced observation files contain only bounded metadata. Upstream and
client lease observations must both be false. Sensitive payload fields (body, lease
values, credentials, secrets, tokens, passwords) and unknown fields are
rejected. The supported cases are `p1_allow`, `p1_deny`, `p2_allow`,
`p2_deny`, `p2_oversize`, `p3_deny`, `p3_redirect`, `p4_safe`,
`p4_strict`, `metadata_omitted`, and `p2_to_p3_timeout`.

Case labels select lifecycle consistency checks; they are not assertions that
a named rule or catalog vector ran. An allow control must still contain the
complete P1--P4 lifecycle on its single receipt. The verifier checks raw
records rather than labels: `p1_allow` and `p2_allow` require raw P1/P2 allow
decisions, a 2xx client status, upstream response observation, and no request
termination; request-side host actions are rejected. `p1_deny`
requires a P1 deny decision and matching client-visible 4xx/5xx status,
request termination, and no upstream response observation. `p2_deny` and
`p2_oversize` require P1 allow/P2 deny sequence; `p2_oversize` additionally
requires matching native P2, request-side deny and client status (403 or 413).
A host-buffer 413 without native P2 is not this case's lifecycle evidence.
`p3_deny` and `p3_redirect` require P3 deny/redirect,
matching client status, and upstream-response observation. `p3_redirect` also
requires a true `redirect_location_verified` attestation: the trusted client
boundary must have observed exactly one `Location` field matching the canonical
bounded target, while the receipt retains only that boolean and never the
header value.
`p4_safe` requires a P4 observer decision, a raw `host_action` of `log_only`,
a committed upstream response, and a client outcome of `none`. `p4_strict` is
always `NON_PASS` in this harness: a driver-side assertion of `abort` or
`reset` is not independent evidence of a client-visible Envoy/Traefik host
primitive. Such a result needs separate real-host proof.

`metadata_omitted` is intentionally pre-admission: the outer companion may
reserve privately, but the explicit ForwardAuth request allow-list omits the
lease, so ForwardAuth returns HTTP 503 before Common P1/P2 exists. Its receipt
therefore contains no P1--P4 or lease event and exactly one terminal `abort`
cleanup, with neither upstream nor committed client response. A missing UDS
before reservation is likewise a pre-admission transport failure, so the
runner refuses to label it as correlated composite evidence instead of
inventing a transaction receipt.

`p2_to_p3_timeout` requires raw P1/P2 `allow` records, one generated lease,
an upstream request observation without a P3/P4 record, HTTP 503, no committed
P4 client response, and one final `terminal` record with `reason` `timeout`.
The Traefik helper selects its fixed response-header delay only from the exact
owner-controlled runtime-root case suffix; catalog input cannot activate that
transport behavior. This is a fail-closed lifecycle control, not proof of a
client-visible P4 abort or reset.

Exit status is `0` only for `LIFECYCLE_ONLY`; malformed and `NON_PASS` receipts
exit `1`. JSON output is payload-free and contains only status, scope,
catalog-acceptance flag, connector, case, artifact ID, decision ID, applicable
phases, and concise errors.

`--expected-event-log` is optional for standalone use. When supplied it must
be an absolute existing regular non-symlink file, and its resolved path must
match the event-log basename referenced by the manifest exactly.
