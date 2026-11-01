"""Propose 35-field case packets from fresh physical receipts for Root review.

No value is sourced from another logical leg, and no packet self-qualifies.
"""
import argparse
import json
from pathlib import Path
import connector_suite.adapters.traefik.harness.i12_auth.review as review

AUDIT_FILE = 'native-audit.log'
COMMAND_SUFFIX = '.command.json'

MAPPING={
 'traefik-forwardauth-request':{'allow':'allow_without_marker','p1-deny':'deny_header_marker_403','p2-deny':'deny_request_body_marker_403'},
 'traefik-forwardauth-response-companion':{'p3-deny':'deny_response_header_marker_403','p4-safe':'phase4_rule_observed'}}


def propose(observed,leg,inventory,destination):
    result=review.read(observed);attempt=Path(result['attempt']);data=attempt/'data';source=Path(result['source']);logs=data/'runtime/logs'
    destination.mkdir(exist_ok=True)
    selected={r['selected_requirement']['case_id']:r for r in review.read(inventory)['rows'] if r['leg_id']==leg}
    packets=[]
    def ref(p,role):return review.reference(p,role)
    nr=ref(logs/'native-lifecycle.jsonl','native_api');hr=ref(logs/'host-lifecycle.jsonl','host_callback')
    source_ref=ref(source/'connectors/profile_registry.c','source_contract')
    debug=ref(logs/'native-debug.log','native_debug');sink=ref(logs/'events.jsonl','physical_event_sink')
    isolation=ref(attempt/'controller-result.json','isolation_receipt')
    for name,case in MAPPING[leg].items():
        if case not in selected:continue
        item=result['cases'][name];scope=item['native_scope'];client=item['client'];framing=item['framing']
        if scope is None:continue
        identity=client['transaction_id'];counts=scope['counts'];returns=scope['returns']
        cp=ref(data/'client'/(name+'.receipt.json'),'client_process');wire=ref(data/'client'/(name+'.response.raw'),'client_process')
        bp=ref(data/'backend/receipts.jsonl','backend_process');cleanup=ref(data/'result.json','cleanup_observer')
        before=result['snapshots']['before-target'];after=result['snapshots']['after-'+name]
        common=next((r for r in returns if r['function']=='common_init'),None)
        def filtered(*functions):return [r for r in returns if r['function'] in functions]
        def obs(value,*evidence):return {'value':value,'applicable':True,'evidence':list(evidence)}
        observations={
          'product_host_identity':obs({'actual_loaded_images':before['processes'],'build_host_sha256':result['build']['host_sha256']},ref(data/'before-target.json','loaded_image'),isolation),
          'source_config_binding':obs({'source_inputs':result['build']['source_inputs'],'configuration':result['build']['configuration']},ref(data/'build-manifest.json','source_manifest'),ref(data/'runtime/effective-config/traefik-forwardauth.conf','effective_configuration'),ref(data/'runtime/effective-config/traefik-forwardauth-dynamic.yaml','effective_configuration')),
          'capability':obs({'product_profile':'traefik-forwardauth','selected_logical_leg':leg,'native_request_phases':[1,2],'native_companion_response_phases':[3,4],'physical_transaction_id':identity},hr,source_ref),
          'client_exit':obs(review.read(data/('client-'+name+COMMAND_SUFFIX))['exit_code'],ref(data/('client-'+name+COMMAND_SUFFIX),'client_process')),
          'client_signal':obs(None,cp),
          'client_headers':obs(framing.get('headers'),wire),
          'client_bytes':obs(framing['entity_bytes'],wire),
          'client_sha256':obs(framing['entity_sha256'],wire),
          'backend_request_count':obs(len(item['backend']),bp),
          'backend_payload_identity':obs({'backend':item['backend'],'client':client,'backend_excluded':not item['backend']},bp,cp),
          'client_backend_correlation':obs({'selected_transaction_id':identity,'actual_backend':item['backend'],'client':client},bp,cp),
          'native_events':obs({'common':scope['common_events'],'native_audit_transaction_id':identity},sink,ref(logs/AUDIT_FILE,'physical_event_sink')),
          'native_api_returns':obs({'counts':counts,'allocation_scope_call':scope['allocation_scope_call'],'all_returns_in_review':str(observed)},nr),
          'native_transaction_id':obs({'value':scope['native_allocation']['transaction_id'],'origin':scope['native_allocation']['transaction_id_origin']},nr),
          'common_transaction_id':obs({'value':common['transaction_id'],'canonical':common['canonical_transaction_id']} if common else None,nr),
          'observed_handle_association':obs({'allocation':scope['native_allocation'],'typed_association_returns':filtered('companion_registered','companion_claimed','companion_retired')},nr),
          'native_phases':obs({'actual_native_calls':{key:value for key,value in counts.items() if key.startswith('native_process_')},'positive_debug':scope['debug_rows']},nr,debug),
          'native_body_chunks':obs({'request_appends':filtered('native_append_request_body'),'response_appends':filtered('native_append_response_body'),'argument_eos_unavailable':True},nr),
          'native_intervention_or_first_cause':obs({'actual_interventions':filtered('native_intervention'),'events':scope['common_events']},nr),
          'host_eos':obs({'finite_request_eos':filtered('authorization_request_eos'),'response_eos_frames':[r for r in scope['host_rows'] if r['fields'].get('opcode')==4]},ref(logs/'native-lifecycle.jsonl','host_callback'),hr),
          'native_eos':obs({'request_native_p2_count':counts.get('native_process_request_body',0),'response_native_p4_count':counts.get('native_process_response_body',0),'request_finish':filtered('runtime_finish_request_body'),'response_finish':filtered('companion_session_finish_response_body'),'no_eof_inference':True},nr,hr),
          'commit_order':obs({'actual_host_rows':scope['host_rows'],'client_first_recv_monotonic_ns':client.get('first_recv_ns'),'header_writer_return_is_separate_from_wire_commit':True,'actual_client_status':framing.get('status'),'native_response_phase_reached':counts.get('native_process_response_headers',0)>0},hr,ref(logs/'traefik-access.log','host_callback'),cp),
          'mime_gate':obs({'actual_debug':scope['debug_rows'],'actual_common_events':scope['common_events'],'native_response_phase_reached':counts.get('native_process_response_headers',0)>0,'early_request_denial_has_no_native_response_mime_evaluation':counts.get('native_process_response_headers',0)==0},debug,sink),
          'finish_calls':obs({'native_logging':counts.get('native_process_logging',0),'common_finish_invocations':counts.get('common_finish',0),'companion_release':counts.get('companion_session_release',0),'same_TU_runtime_finish_not_claimed_wrapped':True},nr),
          'finish_transitions':obs(scope['status_transitions'],nr),
          'native_free_calls':obs(counts.get('native_cleanup',0),nr),
          'cleanup_receipts':obs({'driver':result['driver'],'observer_final':result['observer_final']},cleanup,isolation),
          'descriptor_cleanup':obs({'before':{key:r['fds'] for key,r in before['processes'].items()},'after_case':{key:r['fds'] for key,r in after['processes'].items()},'native_free':counts.get('native_cleanup',0),'retained_listener_is_owned_until_stop':True},ref(data/'before-target.json','cleanup_observer'),ref(data/('after-'+name+'.json'),'cleanup_observer'),cleanup),
          'process_listener_cleanup':obs({'controller_survivors':result['controller']['surviving_namespace_pids'],'outside_mount_leaks':result['controller']['outside_mount_leaks'],'socket_removed':result['driver']['socket_removed'],'processes':result['driver']['processes']},cleanup,isolation),
          'neighbor_health':obs(result['cases'].get('neighbor'),ref(data/'client/neighbor.receipt.json','client_process'),bp),
          'transport_framing':obs(framing,wire),
          'transport_reset_scope':obs({'client_eof':client['tcp_eof_observed'],'complete_framing':framing['complete'],'host_rows':scope['host_rows'],'reset_not_inferred_from_eof':True},cp,hr),
          'host_action':obs({'actual_host_rows':scope['host_rows'],'access_log_status_separate_from_client':True,'actual_client_status':framing.get('status')},hr,ref(logs/'traefik-access.log','host_callback'),cp),
          'physical_event_order':obs({'actual_common_events':scope['common_events'],'native_event_sequences':[r['sequence'] for r in scope['all_calls']]},sink,ref(logs/AUDIT_FILE,'physical_event_sink')),
          'terminal_event_count':obs({'common_event_count':len(scope['common_events']),'native_logging_calls':counts.get('native_process_logging',0),'native_cleanup_calls':counts.get('native_cleanup',0)},sink,ref(logs/AUDIT_FILE,'physical_event_sink'))}
        # An actual successful waited subprocess return proves absence of a terminating signal.
        code=observations['client_exit']['value']
        observations['client_signal']=obs(-code if code<0 else 0,ref(data/('client-'+name+COMMAND_SUFFIX),'client_process'))
        for field,value in observations.items():
            if value['value'] is None:value['reason']='This capture did not observe '+field
        row=selected[case];packet={'run_scoped_case_id':row['run_scoped_case_id'],'leg_id':leg,'fixture_case_id':name,
          'reviewed_by':'pending_root','execution_observed':True,'execution_kind':'host_http','run_id':result['build']['run'],
          'parent_sha':review.read(inventory)['parent_sha'],'framework_sha':None,'mrts_sha':None,
          'effective_config_sha256':review.sha((data/'runtime/effective-config/traefik-forwardauth.conf').read_bytes()),
          'observations':observations,'original_expected_oracle':row['selected_requirement']['expected_oracle'],
          'oracle_evaluated':False,'outcome':None,'full_lifecycle_qualified':False,
          'measurement_review':review.reference(observed,'native_api'),
          'scope_note':'Independent execution for this logical leg; case uses explicit fixture and allocation-scope join; extra phases are retained separately.'}
        path=destination/(case+'.json');path.write_text(json.dumps(packet,indent=2)+'\n');packets.append(path)
    return packets

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for option in ('observed','inventory','destination'):parser.add_argument('--'+option,type=Path,required=True)
    parser.add_argument('--leg',required=True);args=parser.parse_args()
    print(json.dumps([str(p) for p in propose(args.observed,args.leg,args.inventory,args.destination)]))
