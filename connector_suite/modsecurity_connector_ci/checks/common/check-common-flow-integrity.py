from modsecurity_test_framework.connector_context import connector_root
#!/usr/bin/env python3
from pathlib import Path
import sys
root=connector_root()
text='\n'.join((root/p).read_text(errors='ignore') for p in ['common/include/msconnector/flow_guard.h','common/src/flow_guard.c','common/include/msconnector/integrity_event.h','common/src/integrity_event.c','common/include/msconnector/event_jsonl.h','common/src/event_jsonl.c','common/src/event.c'])
err=[]
for term in ['msconnector_integrity_event_hash','msconnector_integrity_event_chain_verify','previous_hash','event_hash','sequence','previous_event_hash']:
    if term not in text: err.append(f'missing {term}')
for field in ['request_body','response_body','body_payload']:
    if field in text: err.append(f'body payload field present: {field}')
if 'msconnector_event_write_jsonl_line' not in text: err.append('JSONL API missing')
if err:
    print('\n'.join(err)); sys.exit(1)
print('common flow integrity: ok')
