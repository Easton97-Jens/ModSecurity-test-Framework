Generated file — do not edit manually.

# Generated Coverage Summary

- Total cases: 161
- RESPONSE_BODY cases: 25
- Verified runtime cases: 0
- Non-verified runtime cases: 161

## By scope
- common: 154
- apache: 0
- nginx: 7
- unknown: 0

## By source
- ModSecurity-apache PR: 4
- mrts: 20
- owasp-modsecurity/ModSecurity-apache#78: 3
- unknown: 134

## MRTS Source Summary
- Total MRTS imported cases: **20**
- Active MRTS cases: **19**
- Pending MRTS cases: **1**
- Unclassified MRTS cases: **0**
- Phase 4 / RESPONSE_BODY MRTS cases: **1**
- Runtime-executable MRTS cases: **19**

## By status
- active: 27
- imported: 133
- pending: 1

## By variable/collection
- `RESPONSE_BODY`: 21
- `ARGS:q`: 18
- `ARGS`: 16
- `REQUEST_BODY`: 11
- `REQUEST_URI`: 8
- `ARGS_NAMES`: 7
- `ARGS:test`: 6
- `REQUEST_HEADERS_NAMES`: 5
- `XML`: 5
- `ARGS:a`: 4
- `REQUEST_COOKIES_NAMES`: 4
- `ARGS:param1`: 4
- `RESPONSE_HEADERS:Set-Cookie`: 4
- `ARGS:probe`: 4
- `MULTIPART_FILENAME`: 3
- `ARGS:chain_a`: 3
- `ARGS:chain_b`: 3
- `FILES`: 2
- `FILES_NAMES`: 2
- `TX:SCORE`: 2
- `REQUEST_COOKIES:USER_TOKEN`: 2
- `RESPONSE_HEADERS:Location`: 2
- `ARGS:audit`: 1
- `REQUEST_HEADERS:X-PR70-Phase`: 1
- `ARGS_POST:arg1`: 1
- `RESPONSE_HEADERS:Last-Modified`: 1
- `ARGS:foo`: 1
- `ARGS:name`: 1
- `FILES_COMBINED_SIZE`: 1
- `FILES:filedata1`: 1
- `XML:/*`: 1
- `REQUEST_HEADERS:X-Missing`: 1
- `REQUEST_HEADERS:X-Phase`: 1
- `ARGS_COMBINED_SIZE`: 1
- `ARGS_GET`: 1
- `ARGS_POST_NAMES`: 1
- `ARGS_POST:test`: 1
- `REQUEST_HEADERS:User-Agent`: 1
- `REQUEST_HEADERS:X-Entity-Probe`: 1
- `RESPONSE_HEADERS:Content-Type`: 1
- `RESPONSE_HEADERS:X-Missing`: 1
- `RESPONSE_HEADERS:content-type`: 1
- `RESPONSE_HEADERS:Server`: 1
- `REQUEST_HEADERS`: 1
- `REQUEST_COOKIES`: 1
- `RESPONSE_HEADERS`: 1

## By phase
- phase 1: 39
- phase 2: 89
- phase 3: 13
- phase 4: 21

## Verification note
- Generated summaries are reporting only and do not replace full runtime evidence from `make smoke-all`.
- RESPONSE_BODY remains non-verified/non-promoted until stable full-smoke runtime evidence exists.
- Bounded Phase 4 / strict-abort evidence remains experimental/non-promoted; pass-through rows do not prove full RESPONSE_BODY support.
