# Framework glossary

**Language:** English | [Deutsch](glossary.de.md)

This glossary defines Framework terms. A newcomer-oriented document should also
give a short local definition when it first uses a term.

| Term | Meaning in this Framework |
|---|---|
| ABI | Application Binary Interface: the binary calling and layout contract between compiled components. |
| ALPN | Application-Layer Protocol Negotiation; the TLS extension used to select an application protocol. |
| API | Application Programming Interface: an explicit program-to-program contract. |
| APXS | Apache eXtenSion tool, normally used to build or install an Apache module. |
| CRS | OWASP Core Rule Set. `no-crs` omits it; `with-crs` loads it before local case rules. |
| EOS | End of stream: the point at which the response stream has ended. |
| Evidence | Payload-safe, attributable artifacts that record what a run observed; evidence is not automatically a PASS promotion. |
| ext_authz | Envoy external authorization filter/integration mode. |
| ext_proc | Envoy external processing filter/integration mode. |
| Full Lifecycle | A causally linked P1–P4 connector run with the required evidence and validation, not merely a build or starter check. |
| HTX | HAProxy internal HTTP representation used by compatible filters. |
| Late Intervention | A decision made after earlier request or response processing; it must not be claimed without causal phase evidence. |
| No-CRS | A test mode that loads only local case rules, without OWASP CRS. |
| P1 / P2 / P3 / P4 | Request headers, request body, response headers, and response body / late response processing phases used by the Framework catalog. |
| Promotion | A validated change from an observed evidence class to a stronger proven status. Promotion is controlled by policy. |
| QUIC | UDP-based secure transport used by HTTP/3. It needs explicit observation evidence when claimed. |
| SPOE / SPOA / SPOP | HAProxy Stream Processing Offload Engine, its agent, and its protocol. |
| TTFB | Time to first byte: elapsed time until the first response byte becomes observable. |
| UDS | Unix domain socket: a local IPC endpoint represented by a filesystem path. |
| Upstream | The service or server behind a proxy/connector that supplies the original response. |
| Wire Body | Bytes observed on the transport wire; this can differ from a decoded or normalized body. |
| Entity Body | The HTTP message body after the applicable transfer/content interpretation. |
| First Byte Before EOS | Evidence that a response byte was observed before end of stream, used to rule out a full-response wait claim. |
| No Full Response Buffering | Evidence that the integration did not require the complete response body to be collected before it could forward a response byte. |

## Status vocabulary

`PASS` means the invoked validation observed the expected condition. `FAIL`
means it observed a contrary condition. `BLOCKED` means a stated prerequisite
was unavailable. `NOT EXECUTED`, `NOT APPLICABLE`, and `UNSUPPORTED` preserve
their respective boundary; none is a PASS by implication.

## Reference boundaries

Catalog terms describe selection and expected behavior. Connector-owned runtime
evidence describes a particular execution. Generated reports summarize inputs;
they do not replace evidence validation. See [variables](variables.md) for
adjustable command inputs.
