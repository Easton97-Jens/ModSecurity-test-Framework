#!/usr/bin/env python3
from pathlib import Path
import re, sys
ROOT=Path(__file__).resolve().parents[3]
BASE=ROOT/'tests/cases/security-data-flow'
REQUIRED=[
'headers/header_count_limit_exceeded.yaml','headers/header_value_limit_exceeded.yaml','headers/conflicting_content_length_rejected.yaml','body-limits/request_body_limit_exceeded.yaml','body-limits/response_body_truncation_event.yaml','transaction-id/transaction_id_control_char_rejected.yaml','transaction-id/transaction_id_too_long_rejected.yaml','events/decision_jsonl_no_body_payload.yaml','events/event_jsonl_no_body_payload.yaml','events/integrity_event_hash_chain_valid.yaml','events/integrity_event_hash_chain_tamper_detected.yaml','phase-order/phase_skip_rejected.yaml','phase-order/duplicate_mutating_phase_rejected.yaml','log-safety/log_control_chars_sanitized.yaml','log-safety/log_secret_like_payload_redacted.yaml']
SECRET_PATTERNS=[r'AWS_SECRET',r'BEGIN PRIVATE KEY',r'sk-[A-Za-z0-9]',r'password=real',r'token=real']
BODY_FIELDS=['request_body','response_body','body_payload','raw_body','payload']

def main():
    errors=[]; names={}
    for rel in REQUIRED:
        p=BASE/rel
        if not p.exists(): errors.append(f'missing {p}'); continue
        text=p.read_text()
        m=re.search(r'^name:\s*([A-Za-z0-9_.-]+)\s*$', text, re.M)
        if not m: errors.append(f'{p}: missing name')
        elif m.group(1) in names: errors.append(f'{p}: duplicate name {m.group(1)}')
        else: names[m.group(1)]=p
        if 'security-data-flow' not in text: errors.append(f'{p}: missing security-data-flow tag')
        if not re.search(r'^(description|known_limitations|former_xfail_reason):', text, re.M): errors.append(f'{p}: missing description/metadata')
        for pat in SECRET_PATTERNS:
            if re.search(pat,text): errors.append(f'{p}: possible real secret pattern {pat}')
        if any(len(line)>4096 for line in text.splitlines()) or len(text)>20000: errors.append(f'{p}: possible huge inline payload')
        if '/events/' in p.as_posix():
            forbidden=[f for f in BODY_FIELDS if re.search(rf'^\s*{re.escape(f)}\s*:', text, re.M)]
            if forbidden: errors.append(f'{p}: event/decision case contains expected body payload fields {forbidden}')
        if re.search(r'runtime_verified:\s*true', text, re.I): errors.append(f'{p}: must not be runtime_verified')
        if re.search(r'status:\s*(passed|pass|runtime-verified|verified)', text, re.I): errors.append(f'{p}: must not be automatically runtime verified')
    if errors:
        print('\n'.join(errors), file=sys.stderr); return 1
    print(f'OK: {len(REQUIRED)} security-data-flow cases validated')
    return 0
if __name__=='__main__': raise SystemExit(main())
