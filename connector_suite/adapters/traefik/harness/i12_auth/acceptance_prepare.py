"""Stage the current central capture plus all-ID auth fixtures; never start hosts."""
from modsecurity_test_framework.connector_context import load_source
import argparse
import ast
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys

DRIVER_FILE = 'driver.py'
PREPARATION_RECEIPT = 'acceptance-preparation.json'

HERE=Path(__file__).resolve().parent

def module(path,_name):
 value = load_source(path);return value
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')

def native_hooks(text):
 native=HERE.parent/'i12/native'
 if sha(native/'acceptance_prepare.py')!='cdb09aa6ba3318953f745cb3010485313ebbe3f1708b4cc1ac0f6a39f50cab6e':
  raise ValueError('exact reviewed native acceptance helper required')
 owner=module(native/'acceptance_prepare.py','native_acceptance_prepare_owner')
 return owner.instrument_fault_hooks(text)


def patch_host_observer(source,cases):
 path=source/'connectors/traefik/response_observer/i12_observer.go';text=path.read_text();original=text;before=sha(path)
 start=text.index('\tif transactionID != ');end=text.index(' {\n\t\treturn',start)
 controls_owner=module(HERE/'acceptance_controls.py','auth_acceptance_control_owner')
 all_cases=[value for case in cases for value in [case,*controls_owner.controls(case)]]
 admitted=[value for case in all_cases for value in (case['probe_id'],case['probe_id']+'-neighbor',case['probe_id']+'-before-neighbor')]
 admitted += [case['fixture']['sink_positive_control']['probe_id'] for case in all_cases if case['fixture'].get('sink_positive_control')]
 admitted += [case['probe_id']+'-ready-'+str(index)+'-neighbor' for case in all_cases for index in range(10)]
 admitted += [case['probe_id']+'-seq-'+str(index) for case in all_cases if len(case['fixture'].get('client',{}).get('sequence',[]))>1 for index in range(3)]
 text=text[:start]+'\tif '+' && '.join('transactionID != '+json.dumps(value) for value in admitted)+text[end:]
 text=text.replace('var i12ObserverPath = "/task/runtime/logs/host-lifecycle.jsonl"','var i12ObserverPath = os.Getenv("I12_ACCEPTANCE_HOST_LOG")')
 marker='return request.Header.Get("X-Request-Id")'
 if text.count(marker)!=1:raise ValueError('exact host probe header boundary required')
 text=text.replace(marker,'return request.Header.Get("X-I12-Probe")')
 path.write_text(text)
 return {'path':str(path.relative_to(source)),'before_sha256':before,'after_sha256':sha(path),
  'unified_diff':''.join(difflib.unified_diff(original.splitlines(True),text.splitlines(True),fromfile='before/'+str(path.relative_to(source)),tofile='after/'+str(path.relative_to(source)))),
  'purpose':'exact admitted synthetic probeIDs; physicalsink relocated by test-only environment; nativeID separately observed'}


def bind_selected_file_cases(selected_ids, selected, contract, files, manifest_path, file_root):
 for original_id in selected_ids:
  case=selected[original_id];direction={'NEED-request-file':'request','NEED-response-file':'response'}.get(case['case_id'])
  expected_route='traefik-forwardauth-'+('request' if direction=='request' else 'response-companion')
  if (case['classification']!='file-capability' or direction is None or case['route']!=expected_route or
      original_id!='I12::'+expected_route+'::'+case['case_id']):
   raise ValueError('only exact ForwardAuth physical file-capability IDs may be admitted')
  declared=[row for row in contract.cases() if row['id']==original_id and row['control']=='benign']
  if len(declared)!=1:raise ValueError('independent File4 benign contract required')
  declared=declared[0]
  fixture=case['fixture'];before=case['fixture_sha256']
  fixture['physical_file_supplement']={'schema':'traefik-auth-physical-file-http-v1','direction':direction,
   'explicit_original_id':original_id,'fixture':'benign.txt','manifest_sha256':sha(manifest_path),
   'files':files,'native_file_api':False,'host_capacity_control':False,
   'original_fixture_sha256':before,'rules_source_sha256':sha(file_root/'acceptance.py'),
   'rules_sha256':declared['rules_sha256'],'qualification':None}
  fixture['rules_lines']=list(declared['rules_lines'])
  fixture['backend']={'status':200,'headers':[['Content-Type','text/plain']],
   'body_hex':contract.BACKEND_BODY.hex(),'chunk_lengths':[len(contract.BACKEND_BODY)]}
  fixture['request'].update(method='POST' if direction=='request' else 'GET',
   uri='/no-crs/request-body' if direction=='request' else '/no-crs/allow',body_hex='',chunk_lengths=[],
   headers=[['Content-Type','text/plain'],['X-I12-Acceptance-Key',case['probe_id']]])
  fixture['policy']['phase4_mode']='safe';fixture['fault']=None;fixture['relay']={}
  fixture['client']={'kind':'ordinary'};fixture['source_overrides']={}
  case['independent_control_expectation']={'source':'explicit benign physical regular-file HTTP supplement',
   'visible_status':200,'authorization_arrivals':1,'native_transactions':1,'backend_arrivals':1,
   'native_file_api':False,'observer_mode':'trusted-provenance','outer_provenance_enabled':True,
   'native_eos_and_finish_free_required':True,'actual_commit_and_client_bytes_required':direction=='response',
   'generic_file_contract':declared['expected'],'generic_transport_is_not_selected_auth_observer_mode':True}
  case['fixture_sha256']=hashlib.sha256(json.dumps(fixture,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def validate_file_fixtures(files, source_root, contract):
 for filename,entry in files.items():
  path=source_root/filename
  if ((entry['size'],entry['sha256'])!=contract.FIXTURES[filename] or path.is_symlink() or
      not path.is_file() or path.stat().st_size!=entry['size'] or sha(path)!=entry['sha256']):
   raise ValueError('exact physical file fixture required: '+filename)


def select_cases(cases, selected_ids):
 if selected_ids:
  if len(set(selected_ids))!=len(selected_ids) or not set(selected_ids)<={case['id'] for case in cases}:
   raise ValueError('selection must name distinct original IDs in the selected route')
  cases=[case for case in cases if case['id'] in selected_ids]
 return cases


def stage_syscall_observer(cases, fixtures):
 if any(case['fixture'].get('syscall_observer') for case in cases):
  tracer=HERE.parent/'i12/native/acceptance_syscalls.c'
  if sha(tracer)!='ec92aed0ca769a6a5136c5f1f32725203b7e7b7c37f6bfadcef54f263462661b':
   raise ValueError('Root reviewed exact-child auth tracer source required')
  shutil.copyfile(tracer,fixtures/'acceptance_syscalls.c')


def bind_file_supplements(cases, selected_ids, repository, fixtures):
 if not selected_ids:return []
 selected={case['id']:case for case in cases}
 if len(set(selected_ids))!=len(selected_ids) or not set(selected_ids)<=set(selected):
  raise ValueError('file supplements must name distinct selected original IDs')
 file_root=repository/'connectors/traefik/harness/i12_file'
 contract=module(file_root/'acceptance.py','auth_physical_file_contract')
 source_root=repository/'connectors/traefik/harness/fixtures/i12-file-source'
 manifest_path=source_root/'manifest.json';manifest=json.loads(manifest_path.read_text())
 if manifest.get('schema')!='traefik-physical-file-fixtures-v1' or manifest.get('native_file_api') is not False:
  raise ValueError('physical HTTP file manifest required')
 files={entry['relative_path']:entry for entry in manifest['files']}
 if set(files)!={'benign.txt','request-marker.txt','request-outside-sample.txt','response-marker.txt'}:
  raise ValueError('all four physical file controls required')
 validate_file_fixtures(files, source_root, contract)
 bind_selected_file_cases(selected_ids, selected, contract, files, manifest_path, file_root)
 target=fixtures/'i12_file';target.mkdir()
 for path in file_root.iterdir():
  if path.is_file() and path.suffix in ('.py','.json','.c','.md'):shutil.copyfile(path,target/path.name)
 shutil.copyfile(manifest_path,target/'manifest.json')
 physical=target/'source-fixtures';physical.mkdir()
 for filename in files:shutil.copyfile(source_root/filename,physical/filename)
 return list(selected_ids)


def prepare(repository,output,manifest_path,route,sdk_controls,selected_ids=None,file_supplement_ids=None):
 owner=module(HERE/'prepare.py','auth_capture_prepare_owner')
 output=owner.validate_output(output);manifest=json.loads(manifest_path.read_text())
 cases=[case for case in manifest['cases'] if case['route']==route]
 if len(cases)!={'traefik-forwardauth-request':93,'traefik-forwardauth-response-companion':69}[route]:raise ValueError('complete original logical route required')
 inventory_count=len(cases)
 cases=select_cases(cases, selected_ids)
 output.mkdir(mode=0o700,parents=True)
 source=owner.stage_source(repository.resolve(),output);fixtures=output/'fixtures';fixtures.mkdir()
 sdk_receipt=json.loads(sdk_controls.read_text())
 if sdk_receipt.get('all_pass') is not True or sdk_receipt.get('host_execution') is not False:
  raise ValueError('independent connector-free SDK controls required before host preparation')
 if sdk_receipt.get('installed_sdk_library',{}).get('sha256')!='32257230b8f378987ba1204049dcc1e23927fd44c8778e09d41805ad705c3407':
  raise ValueError('reviewed SDK identity required')
 shutil.copyfile(sdk_controls,fixtures/'method-uri-sdk-controls.json')
 file_ids=bind_file_supplements(cases,file_supplement_ids,repository.resolve(),fixtures)
 captured=source/'.i12-capture/traefik-forwardauth/drivers'
 for name in (DRIVER_FILE,'cc-wrapper.sh','cxx-wrapper.sh','sdk-who.c'):
  target=fixtures/('base_driver.py' if name==DRIVER_FILE else name);shutil.copyfile(captured/name,target)
  if name.endswith('.sh'):target.chmod(0o755)
 deltas=[patch_host_observer(source,cases)]
 observer=source/'ci/runtime/lifecycle/native-lifecycle-observer.c';before=sha(observer)
 original=observer.read_text();observer.write_text(native_hooks(original))
 (fixtures/'native-observer-before.c').write_text(original)
 deltas.append({'path':str(observer.relative_to(source)),'before_sha256':before,'after_sha256':sha(observer),
  'unified_diff':''.join(difflib.unified_diff(original.splitlines(True),observer.read_text().splitlines(True),fromfile='before/'+str(observer.relative_to(source)),tofile='after/'+str(observer.relative_to(source)))),
  'purpose':'shared native acceptance fault hooks; actual SDK operation precedes explicitly alteredreturn; constructorsNULLonlywithadmittedfault'})
 for name in ('acceptance_driver.py','acceptance_net.py','acceptance_validate.py','acceptance_controls.py','acceptance_parser.py','acceptance_signal.py','acceptance_command.py','acceptance_readiness.py'):
  shutil.copyfile(HERE/name,fixtures/name)
 shutil.copyfile(HERE.parent/'i12/native/acceptance_faults.c',fixtures/'acceptance_faults.c')
 shutil.copyfile(HERE.parent/'i12/native/acceptance_driver.py',fixtures/'shared_native_acceptance_driver.py')
 stage_syscall_observer(cases, fixtures)
 save(fixtures/'acceptance-manifest.json',{**manifest,'cases':cases,'selected_route':route})
 (fixtures/DRIVER_FILE).write_text("import sys\nsys.path.insert(0,'/mnt/fixtures')\nimport acceptance_driver\nacceptance_driver.main()\n")
 for path in fixtures.rglob('*.py'):ast.parse(path.read_text())
 save(output/PREPARATION_RECEIPT,{'central_variant':'traefik-forwardauth','route':route,
  'source_application_receipt_sha256':sha(source/'i12-source-application-receipt.json'),
  'manifest':{'path':str(manifest_path),'sha256':sha(manifest_path)},'instrumentation_delta':deltas,
  'independent_method_uri_sdk_controls':{'path':str(sdk_controls),'sha256':sha(sdk_controls)},
  'fixture_files':{str(p.relative_to(fixtures)):sha(p) for p in fixtures.rglob('*') if p.is_file()},
  'original_inventory_count':inventory_count,'original_id_count':len(cases),
  'explicit_original_id_selection':selected_ids,'qualification':None,'host_launched':False})
 if file_ids:
  receipt=json.loads((output/PREPARATION_RECEIPT).read_text())
  receipt['explicit_physical_file_supplement_ids']=file_ids
  save(output/PREPARATION_RECEIPT,receipt)
 return output

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 for key in ('repository','output','manifest'):parser.add_argument('--'+key,type=Path,required=True)
 parser.add_argument('--sdk-controls',type=Path,required=True)
 parser.add_argument('--route',choices=('traefik-forwardauth-request','traefik-forwardauth-response-companion'),required=True)
 parser.add_argument('--case-id',action='append')
 parser.add_argument('--file-supplement-id',action='append',help='Explicit original-ID admission of physical file-backed HTTP supplement')
 args=parser.parse_args();print(prepare(args.repository,args.output,args.manifest,args.route,args.sdk_controls,args.case_id,args.file_supplement_id))
