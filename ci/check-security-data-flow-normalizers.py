#!/usr/bin/env python3
from pathlib import Path
import importlib.util, py_compile, sys, json
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
FILES=['tests/normalizers/security_event_normalizer.py','tests/normalizers/decision_jsonl_normalizer.py','tests/normalizers/integrity_hash_chain_normalizer.py']

def load(path):
    spec=importlib.util.spec_from_file_location(path.stem,path); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod

def main():
    errors=[]
    mods=[]
    for rel in FILES:
        p=ROOT/rel
        if not p.exists(): errors.append(f'missing {rel}'); continue
        try: py_compile.compile(str(p), doraise=True)
        except Exception as e: errors.append(f'{rel}: compile failed: {e}'); continue
        try: mods.append(load(p))
        except Exception as e: errors.append(f'{rel}: import failed: {e}')
    if errors: print('\n'.join(errors), file=sys.stderr); return 1
    se, dec, ih = mods
    for mod in mods:
        if not hasattr(mod,'self_test'): errors.append(f'{mod.__name__}: missing self_test')
        else:
            try: mod.self_test()
            except Exception as e: errors.append(f'{mod.__name__}: self_test failed: {e}')
    sample='{"request_body":"x","response_body":"y","body_payload":"z","raw_body":"r"}\n'
    _, errs=se.normalize_jsonl(sample)
    for f in ['request_body','response_body','body_payload','raw_body']:
        if not any(f in e for e in errs): errors.append(f'body payload field not detected: {f}')
    r1={'sequence':1,'previous_event_hash':'','event':'start'}; r1['event_hash']=ih.compute_event_hash(r1)
    bad=json.dumps(r1).replace('start','tampered')
    if not ih.validate_hash_chain(bad)[1]: errors.append('tamper data was not detected')
    if errors: print('\n'.join(errors), file=sys.stderr); return 1
    print('OK: security-data-flow normalizers validated')
    return 0
if __name__=='__main__': raise SystemExit(main())
