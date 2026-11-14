# Native Traefik HTTP/2 acceptance preparation

`traefik_native_h2_acceptance.py` is an explicit opt-in host runner for the
repository native UDS middleware loaded by the pinned Traefik Yaegi interpreter.
It executes seven Safe scenarios and a separate Strict scenario: allow, P1/P2/P3
denial, Safe late P4, Strict late P4, client cancellation and upstream reset.
The project default inventory remains unchanged.

Select `CONNECTOR_ROOT`, exact `CONNECTOR_REVISION`, Framework `TEST_ROOT`, and
its compatible Python environment/PYTHONPATH. The runner requires `--root`,
`--traefik`, `--modsecurity-prefix`, `--socket-parent` and `--mode safe|strict`.
Final delivery verification also supplies `--require-clean`, `--expect-parent`
and `--expect-framework`. Every output root must be fresh, private and below
the configured external runtime root. Run the two modes with distinct roots.

Each scenario uses one verified TLS1.3/ALPN-H2 socket and three actual streams.
A response-producing peer remains active until target native cleanup; a later
allow request uses the same physical socket. Native access records independently
prove HTTP/2, TLS, path, response and physical connection identity. No H1 fallback
or response-body storage is used. First-byte and held-EOS barriers cover late
P4/cancellation/reset. Strict requires the real server RST_STREAM code2.

The native middleware streams request bodies. P2 qualification requires the
actual POST entity, matching native rule/URI/body-byte evidence and client 403;
upstream request headers may already be present before that body decision.
This path does not claim the preauthorization boundary of ForwardAuth. Allow,
Safe and Strict require actual upstream target EOS without a reset confound.

The Framework C link observer enables Common decision and post-native-cleanup
records using the existing trusted-provenance API. Its run label comes solely
from validated launcher environment; its fixed connection label denotes engine
observer scope, with reuse false. It never maps HTTP headers to trusted
provenance and never claims physical connection identity. The wire socket and
native access log prove that independently. Source closure and built artifact
hashes identify the instrumented engine separately from production artifacts.
The engine's P4 inspection EOS can precede a Strict reset; it does not establish
client END_STREAM. The middleware records abort requested and does not fabricate
a completed abort acknowledgement to Common.

The runner publishes PASS only after all selected cases, native access counts,
source admission and owned process/socket/fixture cleanup pass. Missing traffic,
zero/duplicate cleanup, wrong rule/protocol/reset, truncated native records and
lost peer isolation fail. Native compiler/service and prior failure logs remain
in their original run directories. This is preparation evidence, not the full
acceptance campaign or a global capability promotion.

`--fault-event-writer` activates an explicit test-link fputs failure control;
it must fail without publishing acceptance PASS and still clean owned resources.
