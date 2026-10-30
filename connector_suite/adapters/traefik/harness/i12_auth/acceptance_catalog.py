"""Bind every original forwardAuth ID to an executable fixture, never a verdict."""
from modsecurity_test_framework.connector_context import load_source
import argparse
import copy
import hashlib
import importlib.util
import json
import re
from pathlib import Path

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths

ROUTES={'traefik-forwardauth-request':93,'traefik-forwardauth-response-companion':69}
BASE_RULES=['SecRuleEngine On','SecRequestBodyAccess On','SecRequestBodyLimit 2097152',
 'SecRequestBodyNoFilesLimit 2097152','SecRequestBodyLimitAction Reject',
 'SecResponseBodyAccess On','SecResponseBodyLimit 2097152','SecResponseBodyLimitAction Reject',
 'SecResponseBodyMimeType text/plain text/html application/json text/csv']


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def reference(path):return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
def default_fixture(name):
 return {'request':{'method':'POST','uri':'/i12/acceptance/'+name,'headers':[['Content-Type','text/plain']],
   'body_hex':b'i12-acceptance-request'.hex(),'chunk_lengths':[22]},
  'backend':{'status':200,'headers':[['Content-Type','text/plain; charset=utf-8']],
   'body_hex':b'i12-acceptance-response\n'.hex(),'chunk_lengths':[24]},
  'rules_lines':list(BASE_RULES),'policy':{'phase4_mode':'safe'},'fault':None,
  'client':{'kind':'ordinary'},'relay':{},'source_overrides':{}}


def canonical(row,by_name,framework):
 path=Path(__file__).resolve().parent.parent/'i12/native/acceptance_plan.py'
 module = load_source(path)
 baseline=framework/'tests/rules/no-crs-baseline.conf'
 result=module.canonical_fixture(row,by_name,framework,baseline.read_text())
 result['shared_canonical_producer']=reference(path)
 result['baseline_rules_source']=reference(baseline)
 result['client']={'kind':'ordinary'};result['relay']={};result['source_overrides']={}
 adapt_canonical(row,result)
 apply_content_type_variant(row,result,framework)
 return result


def apply_content_type_variant(row,fixture,framework):
 variants={'phase4_in_scope_content_type':'in_scope','phase4_content_type_with_charset':'charset',
  'phase4_out_of_scope_content_type':'out_of_scope','phase4_missing_content_type':'missing'}
 variant=variants.get(row['id'].split('::')[-1])
 if variant is None:return
 import yaml
 path=framework/'tests/cases/no-crs-baseline/full-lifecycle/phase4_content_type.yaml'
 declared=yaml.safe_load(path.read_text())['full_lifecycle']['variants']
 selected=declared[variant]
 if selected is not None and (not isinstance(selected,str) or '\r' in selected or '\n' in selected):
  raise ValueError('exact source-bound content-type variant required')
 headers=[pair for pair in fixture['backend']['headers'] if pair[0].lower()!='content-type']
 if selected is not None:headers.append(['Content-Type',selected])
 fixture['backend']['headers']=headers
 fixture['content_type_variant_source']={'source':reference(path),'variant':variant,'literal':selected,
  'selection_is_not_runtime_inspection_evidence':True}


def adapt_limit(row,fixture):
 request=fixture.get('resolved_catalog_request') or (row['original_catalog_case'] or {}).get('request') or {}
 variant=request.get('limit_variant')
 if not variant:return
 response=row['original_contract']['expected_oracle'].get('phase')==4
 direction='Response' if response else 'Request';key='backend' if response else 'request'
 size=16 if variant=='at_limit' else 17
 fixture[key].update(body_hex=(b'0123456789abcdefX'[:size]).hex(),chunk_lengths=[8,size-8])
 policy='ProcessPartial' if variant=='process_partial' else 'Reject'
 fixture['rules_lines']=[line for line in fixture['rules_lines'] if not line.startswith('Sec'+direction+'BodyLimit')]
 fixture['rules_lines']+=['Sec'+direction+'BodyLimit 16','Sec'+direction+'BodyLimitAction '+policy]
 if not response:fixture['rules_lines']+=['SecRequestBodyNoFilesLimit 16']


def adapt_canonical(row,fixture):
 name=row['id'].split('::')[-1]
 if fixture['backend'].get('barrier'):
  chunks=fixture['backend'].get('chunk_lengths',[])
  if len(chunks)<2 or not isinstance(chunks[0],int) or chunks[0]<=0:
   raise ValueError('source-bound literal prefix barrier required')
  fixture['backend']['barrier_after_bytes']=chunks[0]
  fixture['source_bound_barrier']={'literal_prefix_bytes':chunks[0],
   'release_requires_actual_client_entity_bytes':True,'bounded_deadline_seconds':10,
   'deadline_release_is_not_commit_proof':True}
 if name=='phase3_redirect_before_commit':
  fixture['backend']['headers']=[pair for pair in fixture['backend']['headers'] if pair[0].lower()!='x-modsec-upstream']+[['X-Modsec-Upstream','redirect']]
 adapt_limit(row,fixture)
 if name.startswith('keepalive') or name=='multiple_sequential_requests':
  fixture['client']['sequence']=['allow','deny','allow'] if 'deny' in name or name=='multiple_sequential_requests' else ['allow','allow']
  fixture['client']['keepalive']=name.startswith('keepalive')
 if name in ('event_metadata_truncation','event_json_limit'):fixture['policy']['max_event_json_bytes']=4096
 if 'raw_template' in fixture['request']:fixture['client']['raw_template']=fixture['request']['raw_template']


def apply_transport_fault(fixture, kind, name):
 if kind in ('backend-truncated','native-response-append','peer-postcommit-timeout','client-rst'):
  fixture['backend'].update(body_hex=(b'x'*16384).hex(),chunk_lengths=[8192,8192],barrier_after_bytes=8192)
 if kind=='backend-truncated':fixture['backend']['truncate_after_bytes']=8192
 if kind=='client-rst':fixture['client'].update(kind='rst',after_entity_bytes=8192)
 if kind=='peer-postcommit-timeout':fixture['relay']['companion_fault']='delay-second-body'
 if kind=='peer-timeout':fixture['relay']['companion_fault']='delay-claim'
 if kind in ('peer-invalid-result','peer-oversize'):fixture['relay']['companion_fault']=kind
 if name=='NEED-host-auth-response-32768-bound':fixture['relay']['authorization_body_sizes']=[32768,32769]
 if name=='NEED-32768-auth-response-not-application-response':
  fixture['backend'].update(body_hex=(b'i12-large-response-'+b'x'*40000).hex(),chunk_lengths=[8192,31827])
 if name in ('NEED-host-auth-response-32768-bound','NEED-32768-auth-response-not-application-response'):
  body=bytes.fromhex(fixture['request']['body_hex'])
  fixture['explicit_capacity_fixture_binding']={'actual_request_body_bytes':len(body),
   'actual_request_body_sha256':hashlib.sha256(body).hexdigest(),
   'frozen_proposal_declared_request_bytes':15,'frozen_proposal_length_is_not_used_as_measurement':True,
   'application_response_bytes':len(bytes.fromhex(fixture['backend']['body_hex'])),
   'authorization_response_capacity':32768,'observer_mode':'default-mrc1',
   'outer_provenance_enabled':False,'runtime_inspection_bytes':None}


def normalize_fault(fixture,name,route=None):
 fault=fixture.get('fault');kind=(fault or {}).get('kind','')
 if kind=='physical_sink':kind='sink-'+fault['operation']
 aliases={'early_mapping_failure_cleanup':'mapper-headers-null','transaction_begin_failure_cleanup':'begin-failure','finish_failure_propagation':'finish-failure','first-byte-before-late-error':'native-response-append','sink-openat':'sink-open','early_mapping_failure':'mapper-headers-null','transaction_begin_failure':'begin-failure',
  'finish_failure':'finish-failure','precommit-error':'begin-failure','postcommit-error':'native-response-append',
  'invalid-native-return':'native-invalid-return','timeout':'peer-timeout','budget-precommit':'peer-timeout',
  'budget-postcommit':'peer-postcommit-timeout','engine_timeout_before_commit':'peer-timeout',
  'engine_timeout_after_commit':'peer-postcommit-timeout','client-exit-signal':'client-rst',
  'cancel':'client-rst','abort-reset-observation':'client-rst','incomplete-framing':'backend-truncated',
  'missing-eos':'backend-truncated','invalid-metadata':'peer-invalid-result','invalid-header':'peer-invalid-result',
  'size-overflow':'peer-oversize','response_short_write_resume':'writer-short','response_write_would_block_resume':'writer-would-block'}
 if name=='body_size_nonzero_with_null_data':kind='mapper-body-null'
 if name=='header_count_nonzero_with_null_headers':kind='mapper-headers-null'
 kind=aliases.get(kind,kind)
 if route=='traefik-forwardauth-response-companion' and name=='NEED-invalid-native-return':
  kind='native-response-invalid-return'
 if kind=='sink-close':fixture['fault_scope']='service_shutdown'
 if kind=='sink-open':fixture['fault_scope']='startup_before_traffic'
 if name in ('response_short_write_resume','response_write_would_block_resume'):
  fixture['client'].update(slow_reader=True,receive_buffer=1024,read_delay_seconds=0.01)
  fixture['transport_measurement_required']='actual socket syscall short-write/EAGAIN and resume; slow reader alone is insufficient'
 if fault or kind:fixture['fault']={**(fault or {}),'driver_kind':kind}
 apply_transport_fault(fixture, kind, name)
 return fixture


def validate_rule_bindings(row,fixture):
 rules='\n'.join(fixture['rules_lines'])
 rule_ids=re.findall(r'\bid\s*:\s*(\d+)',rules)
 if len(rule_ids)!=len(set(rule_ids)):raise ValueError('duplicate effective rule IDs: '+row['id'])
 expected=row['original_contract']['expected_oracle'].get('rule_id')
 if expected is not None and str(expected) not in rule_ids:
  raise ValueError('original expected rule absent from effective fixture: '+row['id'])


def build_fixture(row, proposal, planned, by_name, minimal_correction):
 name=row['id'].split('::')[-1]
 fixture=copy.deepcopy(proposal['fixture']) if proposal else canonical(row,by_name,Path(planned['framework_catalog']['path']).parents[3])
 fixture.setdefault('client',{'kind':'ordinary'});fixture.setdefault('relay',{});fixture.setdefault('source_overrides',{})
 if name=='phase4_deny_after_commit_log_only_minimal' and minimal_correction:
  binding=json.loads(minimal_correction.read_text())
  if binding['migration_commit']!='992291e7cf3e6984bf458833408dd0eb21398d9a':raise ValueError('reviewed minimal migration required')
  fixture['policy']['phase4_mode']='off'
  fixture['explicit_source_correction']={'binding':reference(minimal_correction),'original_literal':'minimal','effective_fixture_literal':'off','literal_minimal_negative_control_required':True}
 fixture=normalize_fault(fixture,name,row['route'])
 validate_rule_bindings(row,fixture)
 if row['classification']=='config':fixture['config_case']=name
 if row['classification']=='file-capability':fixture['capability_review_required']=True
 return fixture


def build(inventory,proposals,minimal_correction=None):
 planned=json.loads(inventory.read_text());oracle=json.loads(proposals.read_text())
 proposed={r['id']:r for r in oracle['rows']};cases=[]
 for route,count in ROUTES.items():
  selected=[r for r in planned['rows'] if r['route']==route]
  if len(selected)!=count:raise ValueError('exact original route inventory required')
  by_name={r['id'].split('::')[-1]:r['original_catalog_case'] for r in selected if r['original_catalog_case']}
  for row in selected:
   name=row['id'].split('::')[-1];original=row['original_contract'];proposal=proposed.get(row['id'])
   fixture=build_fixture(row, proposal, planned, by_name, minimal_correction)
   probe='ac-'+hashlib.sha256(row['id'].encode()).hexdigest()[:20]
   cases.append({'id':row['id'],'route':route,'case_id':name,'classification':row['classification'],
     'probe_id':probe,'original_contract':original,'original_contract_sha256':digest(original),
     'oracle_proposal':proposal['expected'] if proposal else None,'oracle_source':reference(proposals) if proposal else None,
     'fixture':fixture,'fixture_sha256':digest(fixture),'qualification':None,'status':'planned'})
 return {'schema':'traefik-i12-acceptance-fixtures-v1','source_inventory':reference(inventory),
  'oracle_proposals':reference(proposals),'original_counts':ROUTES,'cases':cases,'qualification':None}

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 for key in ('inventory','proposals','output'):parser.add_argument('--'+key,type=Path,required=True)
 parser.add_argument('--minimal-correction',type=Path)
 args=parser.parse_args();result=build(args.inventory,args.proposals,args.minimal_correction)
 with i12_paths.new_text(args.output) as stream:json.dump(result,stream,indent=2);stream.write('\n')
 print(json.dumps({'output':str(args.output),'cases':len(result['cases']),'qualified':False}))
