# Security Data Flow Cases

These connector-neutral framework cases model security and data-flow requirements. They are framework cases, not connector implementations. PASS may only come from real connector runtime execution and connector-owned evidence. Event and decision checks must not allow request or response body payloads in logs. Hash-chain checks are evidence and tamper-detection checks; real tamper resistance later requires HMAC/signature support in the connector.
