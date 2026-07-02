# Security Data Flow Framework Tests

These tests define connector-neutral security and data-flow cases in the framework. They do not implement connector code, common runtime code, server adapters, harness entrypoints, adapter metadata, or runtime evidence.

A connector repository must execute these cases and keep runtime evidence in that connector repository. A starter PASS is not runtime evidence, and no case in this category claims production readiness, CRS coverage, a full matrix result, or RESPONSE_BODY verification. RESPONSE_BODY remains unverified until stable connector runtime evidence exists.

## Risks covered

- Header manipulation: header-count limits, oversized values, and conflicting Content-Length handling.
- Body-limit and DoS behavior: deterministic request-body-over-limit policy and response-body truncation evidence.
- Transaction-ID safety: rejection of control characters, CR/LF, non-printable bytes, and overlong IDs unless truncation evidence is explicit.
- Phase order and flow guards: skipped phases and duplicate mutating phase execution must be rejected or marked idempotent/readonly by connector evidence.
- Decision/Event JSONL safety: logs must not contain request or response body payload fields and should expose transaction ID, phase, action/decision, HTTP status, redaction, and truncation hints when connectors provide them.
- Hash-chain/tamper evidence: sequence, previous_event_hash, and event_hash fields can be validated by framework normalizers.
- Log sanitizing/redaction: control characters and secret-like payloads must be sanitized or redacted.

## Hash-chain note

Non-cryptographic or CI-only hash-chain evidence is useful only for smoke tamper detection. Real manipulation resistance requires connector-side HMAC or signatures with secure key handling and append-only storage.
