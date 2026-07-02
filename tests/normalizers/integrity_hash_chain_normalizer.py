"""Normalize and validate connector-neutral event hash-chain evidence."""
from __future__ import annotations
import hashlib, json
from typing import Any
from tests.normalizers.security_event_normalizer import normalize_value, parse_jsonl

def _canonical(row: dict[str, Any]) -> str:
    data={k: normalize_value(v) for k,v in row.items() if k != "event_hash"}
    return json.dumps(data, sort_keys=True, separators=(",",":"))

def compute_event_hash(row: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(row).encode()).hexdigest()

def validate_hash_chain(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    rows, errors = parse_jsonl(text); prev=""
    for idx,row in enumerate(rows,1):
        for key in ("sequence","previous_event_hash","event_hash"):
            if key not in row: errors.append(f"line {idx}: missing {key}")
        if errors: continue
        if row.get("sequence") != idx: errors.append(f"line {idx}: sequence mismatch")
        if row.get("previous_event_hash") != prev: errors.append(f"line {idx}: previous_event_hash mismatch")
        actual=compute_event_hash(row)
        if row.get("event_hash") != actual: errors.append(f"line {idx}: event_hash mismatch")
        prev=str(row.get("event_hash"))
    return rows, errors

def normalize_hash_chain(text: str) -> tuple[str, list[str]]:
    rows, errors = validate_hash_chain(text)
    out=[json.dumps({k:("<event-hash>" if k=="event_hash" else "<previous-event-hash>" if k=="previous_event_hash" and v else normalize_value(v)) for k,v in sorted(r.items())}, sort_keys=True, separators=(",",":")) for r in rows]
    return "\n".join(out), errors

def self_test() -> None:
    r1={"sequence":1,"previous_event_hash":"","event":"start"}; r1["event_hash"]=compute_event_hash(r1)
    r2={"sequence":2,"previous_event_hash":r1["event_hash"],"event":"done"}; r2["event_hash"]=compute_event_hash(r2)
    good="\n".join(json.dumps(r, sort_keys=True) for r in (r1,r2))
    assert not validate_hash_chain(good)[1]
    bad=good.replace('"done"','"tampered"')
    assert validate_hash_chain(bad)[1]

if __name__ == "__main__":
    import sys
    out, errs = normalize_hash_chain(sys.stdin.read())
    sys.stdout.write(out + ("\n" if out else ""))
    for e in errs: print(e, file=sys.stderr)
    raise SystemExit(1 if errs else 0)
