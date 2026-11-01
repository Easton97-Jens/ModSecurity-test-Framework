"""Read immutable physical auth/companion observations; never self-qualify a case."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


def sha(data):return hashlib.sha256(data).hexdigest()
def read(path):return json.loads(path.read_text())
def rows(path):return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
def reference(path,role):
    data=path.read_bytes();return {'path':str(path),'sha256':sha(data),'bytes':len(data),'role':role}


def decode_chunked(value, body):
    entity=bytearray();remaining=body
    try:
        while True:
            line,remaining=remaining.split(b'\r\n',1);size=int(line.split(b';')[0],16)
            if size==0:
                if remaining!=b'\r\n':raise ValueError('unexpected chunk trailers or extra bytes')
                break
            if len(remaining)<size+2 or remaining[size:size+2]!=b'\r\n':raise ValueError('incomplete chunk')
            entity.extend(remaining[:size]);remaining=remaining[size+2:]
        value.update(complete=True,entity_bytes=len(entity),entity_sha256=sha(entity))
    except ValueError as error:value['reason']=str(error)


def framing(raw):
    value={'response_bytes':len(raw),'response_status_lines':raw.count(b'HTTP/1.1 '),
        'complete':False,'entity_bytes':None,'entity_sha256':None}
    if b'\r\n\r\n' not in raw:
        value['reason']='no complete HTTP response headers';return value
    head,body=raw.split(b'\r\n\r\n',1)
    lines=head.decode('iso-8859-1').split('\r\n');value['headers']=lines
    value['status']=int(lines[0].split()[1])
    headers=[line.split(':',1) for line in lines[1:] if ':' in line]
    lengths=[text.strip() for key,text in headers if key.lower()=='content-length']
    transfer=[text.strip().lower() for key,text in headers if key.lower()=='transfer-encoding']
    value.update(content_lengths=lengths,transfer_encoding=transfer,wire_body_bytes=len(body),wire_body_sha256=sha(body))
    if len(lengths)==1 and lengths[0].isdigit() and not transfer:
        value.update(complete=int(lengths[0])==len(body),entity_bytes=len(body),entity_sha256=sha(body))
        if not value['complete']:value['reason']='Content-Length differs from received entity bytes'
    elif transfer==['chunked'] and not lengths:
        decode_chunked(value, body)
    else:value['reason']='unqualified or ambiguous response framing'
    return value


def review(attempt,source,output):
    data=attempt/'data';logs=data/'runtime/logs'
    native=rows(logs/'native-lifecycle.jsonl');host=rows(logs/'host-lifecycle.jsonl')
    events=rows(logs/'events.jsonl');backend=rows(data/'backend/receipts.jsonl')
    debug=(logs/'native-debug.log').read_text().splitlines()
    scopes={}
    for allocation in [r for r in native if r['function']=='native_new_with_id' and r['edge']=='return']:
        scope=allocation['allocation_scope_call'];identity=allocation['transaction_id']
        direct=[r for r in native if r['allocation_scope_call']==scope]
        entered={r['call']:r for r in direct if r['edge']=='enter'}
        all_rows=[r for r in native if r['allocation_scope_call']==scope or r['call'] in entered]
        returns=[r for r in all_rows if r['edge']=='return']
        transitions=[{'function':r['function'],'call':r['call'],'before':entered[r['call']]['contract_state'],'after':r['contract_state']}
            for r in returns if r['call'] in entered and r['contract_state'] is not None and entered[r['call']]['contract_state'] is not None and
            r['contract_state']['status']!=entered[r['call']]['contract_state']['status']]
        scopes[identity]={'allocation_scope_call':scope,'native_allocation':allocation,
            'counts':dict(Counter(r['function'] for r in returns)), 'returns':returns,
            'all_calls':all_rows,'status_transitions':transitions,
            'host_rows':[r for r in host if r['transaction_id']==identity],
            'debug_rows':[line for line in debug if line.startswith('['+identity+']')],
            'common_events':[r for r in events if r.get('transaction_id')==identity]}
    clients={}
    for path in sorted((data/'client').glob('*.receipt.json')):
        client=read(path);name=i12_paths.leaf_name(client['case']);identity=client['transaction_id']
        auth=data/'authorization'/(name+'.receipt.json')
        clients[name]={'client':client,'framing':framing((data/'client'/(name+'.response.raw')).read_bytes()),
            'authorization':read(auth) if auth.exists() else None,
            'backend':[r for r in backend if r['transaction_id']==identity],
            'native_scope':scopes.get(identity),
            'raw_references':[reference(path,'client_process'),reference(data/'client'/(name+'.response.raw'),'client_process'),
                reference(data/'backend/receipts.jsonl','backend_process'),reference(logs/'native-lifecycle.jsonl','native_api'),
                reference(logs/'host-lifecycle.jsonl','host_callback')]}
    snapshots={p.stem:read(p) for p in data.glob('*.json') if p.name.startswith(('before-target','after-'))}
    result={'attempt':str(attempt),'source':str(source),'qualification':'measurements_pending_independent_root_review',
        'controller':read(attempt/'controller-result.json'),'driver':read(data/'result.json'),
        'build':read(data/'build-manifest.json'),'cases':clients,'snapshots':snapshots,
        'observer_final':[r for r in native if r['edge']=='final'],
        'raw_references':[reference(logs/'native-audit.log','physical_event_sink'),reference(logs/'native-debug.log','native_debug'),
            reference(logs/'events.jsonl','physical_event_sink'),reference(attempt/'controller-result.json','isolation_receipt')]}
    i12_paths.create_text(output, json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--attempt',type=Path,required=True)
    parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result=review(args.attempt,args.source,args.output)
    print(json.dumps({'review':str(args.output),'cases':{name:{'status':r['framing'].get('status'),
        'complete':r['framing']['complete'],'entity_bytes':r['framing']['entity_bytes'],
        'backend_count':len(r['backend']),'authorization_status':(r['authorization'] or {}).get('authorization_status')}
        for name,r in result['cases'].items()}}))
