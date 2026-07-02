"""Decision JSONL normalizer that rejects body-payload leakage."""
from __future__ import annotations
from tests.normalizers.security_event_normalizer import BODY_PAYLOAD_FIELDS, find_body_payload_fields, normalize_jsonl, parse_jsonl

def normalize(text: str) -> tuple[str, list[str]]:
    return normalize_jsonl(text)

def self_test() -> None:
    _, errors = normalize('{"decision":"block","request_body":"do-not-log"}\n')
    assert errors and "request_body" in errors[0]

if __name__ == "__main__":
    import sys
    out, errs = normalize(sys.stdin.read())
    sys.stdout.write(out + ("\n" if out else ""))
    for e in errs: print(e, file=sys.stderr)
    raise SystemExit(1 if errs else 0)
