"""Connector-neutral security event JSONL normalizer and safety checks."""
from __future__ import annotations
import json, re
from typing import Any

BODY_PAYLOAD_FIELDS = {"request_body", "response_body", "body_payload", "raw_body", "payload"}
_VOLATILE = [(re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?\b"), "<timestamp>"),(re.compile(r"\b(?:127\.0\.0\.1|localhost):\d+\b"), "<host>:<port>"),(re.compile(r"/[A-Za-z0-9._/-]*(?:ModSecurity|workspace)[A-Za-z0-9._/-]*"), "<path>")]

def parse_jsonl(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    rows=[]; errors=[]
    for no,line in enumerate(text.splitlines(),1):
        if not line.strip(): continue
        try:
            obj=json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"line {no}: invalid JSONL: {e.msg}"); continue
        if not isinstance(obj,dict): errors.append(f"line {no}: JSONL record must be an object"); continue
        rows.append(obj)
    return rows, errors

def find_body_payload_fields(obj: Any, prefix: str="") -> list[str]:
    found=[]
    if isinstance(obj,dict):
        for k,v in obj.items():
            p=f"{prefix}.{k}" if prefix else str(k)
            if k in BODY_PAYLOAD_FIELDS and v not in (None,"",[],{}): found.append(p)
            found.extend(find_body_payload_fields(v,p))
    elif isinstance(obj,list):
        for i,v in enumerate(obj): found.extend(find_body_payload_fields(v,f"{prefix}[{i}]"))
    return found

def normalize_value(v: Any) -> Any:
    if isinstance(v,str):
        out=v
        for pat, repl in _VOLATILE: out=pat.sub(repl,out)
        return out
    if isinstance(v,dict): return {k: normalize_value(v[k]) for k in sorted(v)}
    if isinstance(v,list): return [normalize_value(x) for x in v]
    return v

def normalize_jsonl(text: str) -> tuple[str, list[str]]:
    rows, errors = parse_jsonl(text)
    for i,row in enumerate(rows,1):
        for field in find_body_payload_fields(row): errors.append(f"line {i}: body payload field is not allowed: {field}")
    return "\n".join(json.dumps(normalize_value(r), sort_keys=True, separators=(",",":")) for r in rows), errors

def self_test() -> None:
    normalized, errors = normalize_jsonl('{"timestamp":"2026-07-02T00:00:00Z","transaction_id":"abc","payload":"secret"}\n')
    assert "<timestamp>" in normalized
    assert any("payload" in e for e in errors)

if __name__ == "__main__":
    import sys
    out, errs = normalize_jsonl(sys.stdin.read())
    sys.stdout.write(out + ("\n" if out else ""))
    for e in errs: print(e, file=sys.stderr)
    raise SystemExit(1 if errs else 0)
