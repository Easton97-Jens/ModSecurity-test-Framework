"""Run original-ID forwardAuth fixtures through the real host; no qualification."""
from modsecurity_test_framework.connector_context import load_source
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import time

import base_driver as base
import connector_suite.adapters.traefik.harness.i12_auth.acceptance_controls as acceptance_controls
import connector_suite.adapters.traefik.harness.i12_auth.acceptance_command as acceptance_command
import connector_suite.adapters.traefik.harness.i12_auth.acceptance_readiness as acceptance_readiness
import connector_suite.adapters.traefik.harness.i12_auth.acceptance_validate as acceptance_validate
import stat

LOGS='runtime/logs'
RULES='rules.conf'
ROUTERS='  routers:\n'
COMPANION_SOCKET='sockets/companion.sock'
SERVICES='  services:\n'
PROVENANCE_SOCKET='sockets/provenance.sock'
CASE='case.json'
NET_SCRIPT='acceptance_net.py'
PYTHON='/usr/local/bin/python3'

SOURCE=Path('/mnt/src');FIXTURES=Path('/mnt/fixtures');TASK=Path('/task')
ARTIFACTS=Path('/mnt/artifacts/traefik')
GO_SHA256='548d3c32f83fa81152f543eb1526be7884cfe0526eb5e9ce29d3eca14786e7e0'
CONTROLLER_PATH='/opt/controller:/usr/local/bin:/usr/bin:/usr/sbin:/bin'


def toolchain_environment(inputs):
 if any(key in inputs for key in ('GO','GOROOT','GOTOOLCHAIN')) or inputs.get('PATH')!=CONTROLLER_PATH:
  raise RuntimeError('unchanged controller environment required before private toolchain selection')
 root=Path('/mnt/artifacts/toolchains/go1.27.2');go=root/'bin/go'
 if root.resolve(strict=True)!=root or go.resolve(strict=True)!=go:
  raise RuntimeError('sealed private Go1.27.2 path required')
 if (root/'VERSION').read_text().splitlines()[0]!='go1.27.2' or base.digest(go)!=GO_SHA256:
  raise RuntimeError('sealed private Go1.27.2 binary/VERSION identity differs')
 return {'GO':str(go),'GOROOT':str(root),'PATH':str(root/'bin')+':'+CONTROLLER_PATH,'GOTOOLCHAIN':'local'}


def provenance_socket_receipt(path):
 state=path.lstat();parent=path.parent.lstat()
 receipt={'path':str(path),'inode':state.st_ino,'device':state.st_dev,
  'mode':stat.S_IMODE(state.st_mode),'uid':state.st_uid,'gid':state.st_gid,'is_socket':stat.S_ISSOCK(state.st_mode),
  'parent_mode':stat.S_IMODE(parent.st_mode),'parent_uid':parent.st_uid,'parent_gid':parent.st_gid,
  'parent_inode':parent.st_ino,'parent_device':parent.st_dev,'parent_is_directory':stat.S_ISDIR(parent.st_mode),
  'parent_is_symlink':stat.S_ISLNK(parent.st_mode),'parent_observed_by':'lstat',
  'sealed_contract':acceptance_validate.PROVENANCE_SOCKET_CONTRACT,'monotonic_ns':time.monotonic_ns()}
 if (not receipt['is_socket'] or receipt['mode']!=0o600 or receipt['parent_mode']!=0o700
     or not receipt['parent_is_directory'] or receipt['parent_is_symlink']
     or (parent.st_uid,parent.st_gid)!=(os.geteuid(),os.getegid())
     or (state.st_uid,state.st_gid)!=(os.geteuid(),os.getegid())):
  raise RuntimeError('private MTP1 socket identity invalid')
 return receipt


def module(path,name):
 value = load_source(path);return value


def prepare_build():
 if (os.geteuid(),os.getegid())!=(65534,65534):raise RuntimeError('nonroot admitted identity required')
 for name in ('build','tmp','cache','go-cache','runtime','cases'):(TASK/name).mkdir(mode=0o700)
 host=TASK/'cache/traefik';shutil.copyfile(ARTIFACTS/'host',host);host.chmod(0o700)
 shutil.copytree(ARTIFACTS/'offline-mod',TASK/'go-mod')
 for path in (TASK/'go-mod',*(TASK/'go-mod').rglob('*')):path.chmod(0o700 if path.is_dir() else 0o600)
 toolchain=toolchain_environment(os.environ)
 env=os.environ.copy();env.update(toolchain);env.update(BUILD_ROOT=str(TASK/'build'),TMPDIR=str(TASK/'tmp'),TMP_ROOT=str(TASK/'tmp'),
  GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',GOMODCACHE=str(TASK/'go-mod'),GOCACHE=str(TASK/'go-cache'),
  GOFLAGS='-mod=readonly',CC=str(FIXTURES/'cc-wrapper.sh'),CXX=str(FIXTURES/'cxx-wrapper.sh'),
  MODSECURITY_INCLUDE_DIR='/usr/include',MODSECURITY_LIB_DIR='/usr/lib/x86_64-linux-gnu')
 for label,args,expected in [('go-version',['version'],'go version go1.27.2 linux/amd64'),('go-root',['env','GOROOT'],env['GOROOT'])]:
  base.execute(label,[env['GO'],*args],env)
  if (TASK/(label+'.stdout')).read_text().strip()!=expected:raise RuntimeError('private toolchain runtime identity differs: '+label)
 objects=[]
 recipes=[('observer','gcc','c17',SOURCE/'ci/runtime/lifecycle/native-lifecycle-observer.c'),
  ('sdk-accessor','g++','c++17',SOURCE/'ci/runtime/lifecycle/native-lifecycle-sdk.cpp'),
  ('acceptance-faults','gcc','c17',FIXTURES/'acceptance_faults.c')]
 for label,compiler,standard,source in recipes:
  output=TASK/'build'/(label+'.o');objects.append(output)
  base.execute(label+'-compile',['/usr/bin/'+compiler,'-std='+standard,'-Wall','-Wextra','-Werror','-pthread',
   '-I',SOURCE/'common/include','-c',source,'-o',output],env)
 shared=module(FIXTURES/'shared_native_acceptance_driver.py','shared_acceptance_driver')
 env['TRAEFIK_CONNECTOR_CFLAGS']='-I '+str(SOURCE/'ci/runtime/lifecycle')
 env['TRAEFIK_CONNECTOR_LDFLAGS']=' '.join([*map(str,objects),*( '-Wl,--wrap='+symbol for symbol in (*base.SYMBOLS,*shared.FAULT_SYMBOLS))])
 env['TRAEFIK_CONNECTOR_BUILD_DIR']=str(TASK/'build/service');env['TRAEFIK_CONNECTOR_BIN']=str(TASK/'build/service/traefik-forwardauth')
 base.execute('forwardauth-build',[SOURCE/'connectors/traefik/build/build-connector.sh'],env)
 base.execute('host-version',[host,'version'],env)
 if (FIXTURES/'acceptance_syscalls.c').is_file():
  base.execute('syscall-observer-compile',['/usr/bin/gcc','-std=c17','-Wall','-Wextra','-Werror','-pthread',
   FIXTURES/'acceptance_syscalls.c','-o',TASK/'build/acceptance-syscalls'],env)
 engine=Path(env['TRAEFIK_CONNECTOR_BIN'])
 base.write('acceptance-build.json',{'host_sha256':base.digest(host),'engine_sha256':base.digest(engine),
  'observer_source_sha256':base.digest(recipes[0][3]),'fault_source_sha256':base.digest(recipes[2][3]),
  'manifest_sha256':base.digest(FIXTURES/'acceptance-manifest.json'),'toolchain':dict(toolchain,binary_sha256=base.digest(Path(env['GO']))),
  'fixture_inputs':{str(p.relative_to(FIXTURES)):base.digest(p) for p in FIXTURES.rglob('*') if p.is_file()},
  'source_inputs':{str(p.relative_to(SOURCE)):base.digest(p) for p in SOURCE.rglob('*') if p.is_file()},
  'native_header_inputs':{str(p):base.digest(p) for p in Path('/usr/include/modsecurity').glob('*.h')},'qualification':None})
 return env,engine,host,shared


def configuration(case,root,helper,backend_port,auth_port,companion_socket,file_backend_port=None):
 config_dir=root/'runtime/effective-config';logs=root/LOGS
 config=config_dir/'traefik-forwardauth.conf';rules=root/RULES
 policy=case['fixture'].get('policy',{})
 values={'enabled':'on','rules_file':str(rules),'transaction_id_header':'x-request-id',
  'request_body_mode':'buffered','response_body_mode':'streaming','phase4_mode':policy.get('phase4_mode','safe'),
  'default_block_status':'403','default_error_status':'500','event_path':str(logs/'events.jsonl'),'use_error_log':'on',
  'max_header_count':'128','max_header_name_size':'256','max_header_value_size':'8192','max_total_header_bytes':'65536',
  'max_event_json_bytes':str(policy.get('max_event_json_bytes',16384))}
 if case['case_id']=='transaction_id_generated_or_fallback':values['transaction_id_header']='x-modsec-transaction-id'
 values.update(case['fixture'].get('source_overrides',{}))
 apply_config_case(case,values,rules)
 config.write_text(''.join(key+'='+value+'\n' for key,value in values.items()))
 text=helper.dynamic_config(backend_port,auth_port,companion_socket)
 if '        preserveRequestMethod: true' not in text:raise RuntimeError('integrated trusted-method contract missing')
 if '        maxResponseBodySize: 32768' not in text:
  text=text.replace('        maxBodySize: 4096','        maxBodySize: 4096\n        maxResponseBodySize: 32768')
 names={key for key,_ in case['fixture']['request']['headers']}|{'X-I12-Probe','X-I12-Neighbor','X-Request-Id','Content-Type','Content-Length','X-Modsec-Smoke','X-Modsec-Transaction-Id'}
 names={name for name in names if name.lower() not in (acceptance_validate.RESERVATION.lower(),acceptance_validate.HANDLE.lower())}
 if acceptance_validate.provenance_mode(case):names.add(acceptance_validate.RESERVATION)
 start=text.index('        authRequestHeaders:');end=text.index('        authResponseHeaders:',start)
 text=text[:start]+'        authRequestHeaders:\n'+''.join('        - '+name+'\n' for name in sorted(names))+text[end:]
 timeout=1000 if case['fixture'].get('relay',{}).get('companion_fault') else 5000
 text=text.replace('timeoutMillis: 5000','timeoutMillis: '+str(timeout))
 text=text.replace(ROUTERS,'  routers:\n    healthy-neighbor:\n      entryPoints: [web]\n      rule: Header(`X-I12-Neighbor`, `1`)\n      priority: 100\n      middlewares: [modsecurity-forwardauth, healthy-response-observer]\n      service: upstream\n',1)
 healthy='    healthy-response-observer:\n      plugin:\n        modsecurityResponseObserver:\n          socketPath: '+str(root/COMPANION_SOCKET)+'\n          timeoutMillis: 5000\n'
 text=text.replace(SERVICES,healthy+SERVICES,1)
 if acceptance_validate.provenance_mode(case):text=provenance_configuration(text,case,root,companion_socket,timeout)
 text=file_router_configuration(text,case,file_backend_port,backend_port,auth_port)
 dynamic=config_dir/'traefik-dynamic.yaml';dynamic.write_text(text)
 return config,dynamic


def apply_config_case(case,values,rules):
 name=case['fixture'].get('config_case')
 changes={'unknown_config_key':('acceptance_unknown','on'),'invalid_boolean':('enabled','maybe'),
  'invalid_status':('default_block_status','999'),'invalid_size':('max_header_count','-1'),'unsafe_event_path':('event_path','/dev/null')}
 if name in changes:key,value=changes[name];values[key]=value
 if name=='missing_rules_file':values['rules_file']=str(rules.parent/'missing-rules.conf')
 if name=='invalid_rule_syntax':rules.write_text('SecRule THIS_IS_NOT_A_VALID_RULE\n')


def case_environment(case,root,env,native_fd,fault_fd):
 value=env|{'MSCONNECTOR_LIFECYCLE_FD':str(native_fd),'MSCONNECTOR_LIFECYCLE_RUN':'traefik-acceptance-20261015',
  'MSCONNECTOR_LIFECYCLE_PROFILE':case['route'],'MSCONNECTOR_LIFECYCLE_CASE':case['id'],
  'I12_ACCEPTANCE_EVENT_PATH':str(root/'runtime/logs/events.jsonl'),'I12_ACCEPTANCE_FAULT_URI':case['fixture']['request']['uri'],
  'I12_ACCEPTANCE_FAULT_FD':str(fault_fd),'I12_ACCEPTANCE_HOST_LOG':str(root/'runtime/logs/host-lifecycle.jsonl'),
  'MSCONNECTOR_TRAEFIK_FORWARDAUTH_COMPANION_SOCKET':str(root/COMPANION_SOCKET)}
 if acceptance_validate.provenance_mode(case):value['MSCONNECTOR_TRAEFIK_PROVENANCE_SOCKET']=str(root/PROVENANCE_SOCKET)
 else:value.pop('MSCONNECTOR_TRAEFIK_PROVENANCE_SOCKET',None)
 value['I12_ACCEPTANCE_FAULT']=(case['fixture'].get('fault') or {}).get('driver_kind','')
 return value


def create_case_root(case,shared):
 root=TASK/'cases'/case['probe_id'];root.mkdir(mode=0o700)
 for name in ('runtime',LOGS,'runtime/effective-config','sockets'):(root/name).mkdir(mode=0o700)
 for name in ('native-lifecycle.jsonl','host-lifecycle.jsonl','events.jsonl','audit.log','debug.log'):(root/LOGS/name).touch(mode=0o600)
 (root/CASE).write_text(json.dumps(case,indent=2)+'\n')
 shared.append_rules(root/RULES,case['fixture'],root/LOGS)
 return root


def start_net(label,mode,root,env,handles,processes,helper,port=None,engine_port=None,target=None):
 argv=[PYTHON,'-P',FIXTURES/NET_SCRIPT,mode,'--spec',root/CASE,'--root',root]
 if port is not None:argv+=['--port',port]
 if engine_port is not None:argv+=['--engine-port',engine_port]
 if target is not None:argv+=['--socket',root/'sockets/observer.sock','--target',target]
 process=base.start(label,argv,env,handles);processes[label]=(process,str(FIXTURES/NET_SCRIPT))
 if port is not None:helper.wait_for_tcp(port,process,label)
 return process


def file_command(case,root,mode,port=None):
 binding=acceptance_controls.file_binding(case)
 if not binding:raise ValueError('physical reader requires explicit sealed case binding')
 manifest=FIXTURES/'i12_file/manifest.json'
 content=json.loads(manifest.read_text())
 if (base.digest(manifest)!=binding['manifest_sha256'] or
     base.digest(FIXTURES/'i12_file/acceptance.py')!=binding['rules_source_sha256'] or
     content.get('native_file_api') is not False or
     {entry['relative_path']:entry for entry in content['files']}!=binding['files']):
  raise ValueError('physical reader manifest differs from sealed case')
 argv=[PYTHON,'-P',FIXTURES/'i12_file/run.py',mode,
  '--manifest',manifest,'--private-root',root/'file-source','--evidence-root',root/'file-evidence']
 if mode=='stage':argv+=['--fixture-root',FIXTURES/'i12_file/source-fixtures']
 elif mode in ('client','backend'):
  if type(port) is not int or not 1<=port<=65535:raise ValueError('physical reader requires bounded literal port')
  argv+=['--fixture',binding['fixture'],'--port',str(port),'--key',case['probe_id'],'--transaction-id',case['probe_id']]
  if mode=='client':argv+=['--uri',case['fixture']['request']['uri']]
 else:raise ValueError('physical reader mode not admitted')
 return argv


def file_environment(env):
 # Safe-path removes the script directory. Only this reader child receives the
 # sealed package root; the controller admission and host environment stay exact.
 return env|{'PYTHONPATH':str(FIXTURES/'i12_file')}


def stage_file_source(case,root,env,shared):
 for name in ('file-source','file-evidence'):(root/name).mkdir(mode=0o700)
 command=shared.command('physical-file-stage',file_command(case,root,'stage'),file_environment(env))
 if command['exit_code']!=0:raise RuntimeError('physical file staging failed')
 return command


def start_file_backend(case,root,port,env,handles,processes,seconds=5):
 """Read the single-target backend's listen receipt without consuming its accept."""
 if not 0<seconds<=5:raise ValueError('bounded file backend readiness required')
 process=base.start('physical-file-backend',file_command(case,root,'backend',port),file_environment(env),handles)
 marker=str(FIXTURES/'i12_file/run.py')
 processes['physical-file-backend']=(process,marker)
 path=root/'file-evidence'/(case['probe_id']+'.backend-listening.json')
 deadline=time.monotonic()+seconds
 while time.monotonic()<deadline:
  if process.poll() is not None:raise RuntimeError('physical file backend exited before readiness receipt')
  receipt=file_backend_ready_receipt(path,process,marker,port)
  if receipt is not None:return receipt
  time.sleep(0.01)
 raise RuntimeError('physical file backend listen receipt deadline expired')


def host_argv(helper,host,host_port,dynamic,root):
 return [host,f'--entryPoints.web.address=127.0.0.1:{host_port}',
  f'--experimental.localPlugins.modsecurityResponseObserver.moduleName={helper.OBSERVER_MODULE}',
  '--experimental.localPlugins.modsecurityResponseObserver.settings.useUnsafe=true','--experimental.abortOnPluginFailure=true',
  f'--providers.file.filename={dynamic}','--providers.file.watch=false','--api=false','--log.level=INFO',
  '--global.sendAnonymousUsage=false','--global.checkNewVersion=false','--accesslog=true',
  '--accesslog.filepath='+str(root/'runtime/logs/traefik-access.log')]


def execute_clients(case,root,env,host_port,processes,shared):
 script=FIXTURES/NET_SCRIPT
 common=[PYTHON,'-P',script,'client','--spec',root/CASE,'--root',root,'--port',host_port]
 before=shared.command('client-before-neighbor',[*common,'--neighbor','--before-neighbor'],env);base.snapshot('before-target-healthy',live(processes))
 physical=acceptance_controls.file_binding(case)
 if physical and physical['direction']=='request':
  primary=shared.command('physical-file-client',file_command(case,root,'client',host_port),file_environment(env))
 elif case['fixture'].get('client',{}).get('kind')=='wait-for-sigterm':
  primary=shared.command('client-signal-controller',
   [PYTHON,'-P',FIXTURES/'acceptance_signal.py','--case-root',root,'--port',host_port],env)
  if primary['exit_code']!=0:raise RuntimeError('physical client signal controller failed')
  primary=json.loads((root/'client-target.command.json').read_text())
 elif case['fixture'].get('syscall_observer'):
  primary=acceptance_command.execute(root,'client-target',common,env,120)
 else:primary=shared.command('client-target',common,env)
 base.snapshot('after-target',live(processes))
 positive=None
 if case['fixture'].get('sink_positive_control'):
  positive=shared.command('client-positive',[*common,'--positive-control'],env)
  base.snapshot('after-sink-positive',live(processes))
 delay=5.3 if case['fixture'].get('relay',{}).get('handle') in ('missing','unknown64hex','malformed') or case['fixture'].get('relay',{}).get('authorization_body_size',0)>32768 else 0
 if delay:time.sleep(delay)
 neighbor=shared.command('client-neighbor',[*common,'--neighbor'],env);base.snapshot('after-neighbor',live(processes))
 return {'healthy_before':before,'target':primary,'target_timeout':primary.get('timed_out',False),
  'sink_positive':positive,'neighbor':neighbor,'deferred_cleanup_wait_seconds':delay}


def wait_for_http_ready(case,root,env,host_port,seconds=20):
 if not 0<seconds<=20:raise ValueError('bounded readiness budget required')
 started=time.monotonic_ns();deadline=time.monotonic()+seconds;history=[];ready=False
 if (case['fixture'].get('fault') or {}).get('driver_kind')=='sink-open':
  receipt={'expected_unready_service_startup_failure':True,'ready':False,'attempts':[],
   'started_ns':started,'completed_ns':time.monotonic_ns(),'qualification':None}
 else:
  ready=probe_http_ready(case,root,env,host_port,deadline,history)
  receipt={'ready':ready,'attempts':history,'started_ns':started,'completed_ns':time.monotonic_ns(),
   'tcp_ready_is_not_http_ready':True,'only_startup_404_is_retried':True,
   'startup_attempts_are_not_qualified_before_control':True,'qualification':None}
  receipt.update(deadline_seconds=seconds,deadline_exceeded=time.monotonic()>=deadline,
   deadline_scope='HTTP/native readiness; subprocess timeout reaping separately bounded and recorded')
 (root/'http-readiness.json').write_text(json.dumps(receipt,indent=2)+'\n')
 if not ready and not receipt.get('expected_unready_service_startup_failure'):
  raise RuntimeError('bounded independent HTTP routing readiness did not reach200')
 return receipt


def live(processes):
 return {name:value for name,value in processes.items() if value[0].poll() is None}


def execute_case(case,env,engine,host,shared,helper):
 physical=acceptance_controls.file_binding(case)
 root=create_case_root(case,shared);base.TASK=root;shared.TASK=root
 handles=[];processes={};result={'id':case['id'],'probe_id':case['probe_id'],'qualification':None,'processes':{},
  'control_name':case.get('control_name'),'original_id':case.get('original_id',case['id']),
  'fixture_sha256':case.get('fixture_sha256'),'started_ns':time.monotonic_ns(),
  'independent_control_expectation':case.get('independent_control_expectation')}
 native_fd=os.open(root/'runtime/logs/native-lifecycle.jsonl',os.O_WRONLY|os.O_APPEND)
 fault_path=root/'faults.jsonl';fault_fd=os.open(fault_path,os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
 current=case_environment(case,root,env,native_fd,fault_fd)
 ports=[helper.free_port() for _ in range(4)];backend_port,relay_port,engine_port,host_port=ports
 file_backend_port=None
 if physical and physical['direction']=='response':
  file_backend_port=helper.free_port()
  while file_backend_port in ports:file_backend_port=helper.free_port()
 socket_path=Path(current['MSCONNECTOR_TRAEFIK_FORWARDAUTH_COMPANION_SOCKET'])
 observer_path=root/'sockets/observer.sock' if case['fixture'].get('relay',{}).get('companion_fault') else socket_path
 try:
  config,dynamic=configuration(case,root,helper,backend_port,relay_port,observer_path,file_backend_port)
  result['configuration_sha256']={str(p.relative_to(root)):base.digest(p) for p in (config,dynamic,root/RULES)}
  if not preflight_case(case,root,config,dynamic,engine,env,current,shared,result,physical):return result
  helper.stage_response_observer(SOURCE/'connectors/traefik/response_observer',root/'runtime')
  start_net('backend','backend',root,current,handles,processes,helper,port=backend_port)
  service=start_engine(case,engine,config,engine_port,current,handles,processes,helper,native_fd,fault_fd,fault_path,result)
  if acceptance_validate.provenance_mode(case) and service.poll() is None:
   result['provenance_socket_before']=provenance_socket_receipt(Path(current['MSCONNECTOR_TRAEFIK_PROVENANCE_SOCKET']))
  result['observer_mode']='trusted-provenance' if acceptance_validate.provenance_mode(case) else 'default-mrc1'
  start_net('authorization-relay','relay',root,current,handles,processes,helper,port=relay_port,engine_port=engine_port)
  if observer_path!=socket_path:start_net('companion-proxy','companion-proxy',root,current,handles,processes,helper,target=socket_path)
  argv=measured_host_argv(case,root,helper,host,host_port,dynamic)
  process=base.start('traefik',argv,current,handles);processes['traefik']=(process,str(host))
  helper.wait_for_tcp(host_port,process,'real Traefik')
  result['http_readiness']=wait_for_http_ready(case,root,current,host_port)
  if physical and physical['direction']=='response':
   result['physical_file_backend_readiness']=start_file_backend(case,root,file_backend_port,current,handles,processes)
  base.snapshot('before-target',live(processes))
  result['client_commands']=execute_clients(case,root,current,host_port,processes,shared)
  if result['client_commands'].get('target_timeout'):
   result['producer_error']={'type':'TimeoutExpired','message':'target-only120s client deadline expired; after-control retained'}
 except Exception as error:result['producer_error']={'type':type(error).__name__,'message':str(error)}
 finally:
  cleanup_case(case,root,result,processes,shared,native_fd,fault_fd,handles,socket_path,observer_path)
  base.write('result.json',result)
 return result


def main():
 manifest=json.loads((FIXTURES/'acceptance-manifest.json').read_text())
 env,engine,host,shared=prepare_build();helper=module(SOURCE/'connectors/traefik/scripts/runtime_smoke.py','current_auth_host_helpers')
 results=[]
 try:
  for case in manifest['cases']:
   try:
    controls=acceptance_controls.controls(case)
    before=[execute_case(control,env,engine,host,shared,helper) for control in controls if control.get('control_order')=='before']
    measured=execute_case(case,env,engine,host,shared,helper)
    measured['supplementary_controls']=before
    for control in controls:
     if control.get('control_order')=='before':continue
     measured['supplementary_controls'].append(execute_case(control,env,engine,host,shared,helper))
    results.append(measured)
   except Exception as error:results.append({'id':case['id'],'producer_error':{'type':type(error).__name__,'message':str(error)},'qualification':None})
 finally:
  base.TASK=TASK;base.write('acceptance-execution-summary.json',{'route':manifest['selected_route'],
   'original_ids':len(manifest['cases']),'results':results,'qualification':None,'runtime_source_manifest_sha256':base.digest(TASK/'acceptance-build.json')})
 print(json.dumps({'original_cases':len(results),'producer_complete':len(results)==len(manifest['cases']),'qualified':False}))


def provenance_configuration(text,case,root,companion_socket,timeout):
 for router,observer in [('smoke','modsecurity-response-observer'),('healthy-neighbor','healthy-response-observer')]:
  if router=='smoke':
   text=text.replace('      - modsecurity-forwardauth\n      - '+observer,'      - '+observer+'\n      - modsecurity-forwardauth\n      - '+observer+'-confirm',1)
  else:text=text.replace('middlewares: [modsecurity-forwardauth, '+observer+']','middlewares: ['+observer+', modsecurity-forwardauth, '+observer+'-confirm]')
  socket=str(companion_socket if router=='smoke' else root/COMPANION_SOCKET)
  timeout_value=timeout if router=='smoke' else 5000
  marker='          socketPath: '+socket+'\n          timeoutMillis: '+str(timeout_value)+'\n'
  settings='          provenanceSocketPath: '+str(root/PROVENANCE_SOCKET)+'\n          runID: '+acceptance_validate.RUN_ID+'\n          transportCaseID: '+case['id']+'\n'
  # Replace only the named outer block; sockets may be shared by both routes.
  start=text.index('    '+observer+':\n');end=text.index(marker,start)+len(marker)
  text=text[:end]+settings+text[end:]
  inner='    '+observer+'-confirm:\n      plugin:\n        modsecurityResponseObserver:\n          socketPath: '+socket+'\n          timeoutMillis: '+str(timeout_value)+'\n          confirmProvenance: true\n'
  text=text.replace(SERVICES,inner+SERVICES,1)

 return text


def file_router_configuration(text,case,file_backend_port,backend_port,auth_port):
 physical=acceptance_controls.file_binding(case)
 if physical and physical['direction']=='response':
  if (type(file_backend_port) is not int or not 1<=file_backend_port<=65535 or
      file_backend_port in (backend_port,auth_port) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',case['probe_id'])):
   raise ValueError('separate literal physical file backend port and probe required')
  chain=(['modsecurity-response-observer','modsecurity-forwardauth','modsecurity-response-observer-confirm']
   if acceptance_validate.provenance_mode(case) else ['modsecurity-forwardauth','modsecurity-response-observer'])
  router=('    physical-file-target:\n      entryPoints: [web]\n      rule: Header(`X-I12-Probe`, `'+case['probe_id']+'`) && !Header(`X-I12-Neighbor`, `1`)\n'
   '      priority: 200\n      middlewares: ['+', '.join(chain)+']\n      service: physical-file-backend\n')
  service='    physical-file-backend:\n      loadBalancer:\n        servers:\n        - url: http://127.0.0.1:'+str(file_backend_port)+'\n'
  text=text.replace(ROUTERS,ROUTERS+router,1).replace(SERVICES,SERVICES+service,1)

 return text


def file_backend_ready_receipt(path,process,marker,port):
 if path.is_file() and not path.is_symlink():
  try:receipt=json.loads(path.read_text())
  except json.JSONDecodeError:receipt=None
  if receipt is not None:
   actual_pid=base.actual_pid(process,marker)
   if receipt.get('pid')!=actual_pid or receipt.get('port')!=port:
    raise RuntimeError('physical file backend readiness identity differs')
   return {'receipt':str(path),'sha256':base.digest(path),'pid':actual_pid,'wrapper_pid':process.pid,'port':port,
    'tcp_readiness_probe_performed':False,'native_eos_proven':False}

 return None


def readiness_native(case,root,index,measured,status,command,deadline):
 native=None
 if status==200 and not command['timed_out'] and time.monotonic()<deadline:
  for _ in range(50):
   if time.monotonic()>=deadline:break
   native=acceptance_readiness.native_receipt(root/'runtime/logs/native-lifecycle.jsonl',measured,
    expected_probe=case['probe_id']+'-ready-'+str(index),command=command)
   if native['positive_allocation_finish_free']:break
   remaining=deadline-time.monotonic()
   if remaining<=0:break
   time.sleep(min(0.01,remaining))

 return native


def readiness_attempt(case,root,env,host_port,index,deadline,remaining,history):
 argv=[PYTHON,'-P',FIXTURES/NET_SCRIPT,'client','--spec',root/CASE,
  '--root',root,'--port',host_port,'--neighbor','--readiness-index',index]
 command=acceptance_command.execute(root,'readiness-'+str(index),argv,env,min(3,remaining),absolute_deadline=deadline)
 path=root/('client-readiness-'+str(index)+'.json')
 measured=json.loads(path.read_text()) if path.is_file() else None
 requests=measured.get('requests',[]) if measured else []
 status=requests[0]['client_framing']['status'] if requests else None
 native=readiness_native(case,root,index,measured,status,command,deadline)
 history.append({'index':index,'wire_probe':case['probe_id']+'-ready-'+str(index)+'-neighbor',
  'client_receipt':str(path) if measured else None,'status':status,'command':command,'native_receipt':native})
 return status,command,native


def preflight_case(case,root,config,dynamic,engine,env,current,shared,result,physical):
 validation=shared.command('yaml-preflight',['/usr/bin/python3','-P',FIXTURES/'acceptance_validate.py',dynamic,root/CASE],env)
 if validation['exit_code']!=0:raise RuntimeError('effective YAML contract validation failed')
 if case['classification']=='config':
  controller=shared.command('check-config-controller',
   [PYTHON,'-P',FIXTURES/'acceptance_parser.py','--case-root',root],env)
  if controller['exit_code']!=0:raise RuntimeError('physical parser controller failed')
  check=json.loads((root/'check-config.command.json').read_text())
 else:check=shared.command('check-config',[engine,'--check-config','--config',config],env)
 result['config_check']=check
 if case['classification']=='config':
  result.update(configuration_only=True,transaction_allocations_expected=0,
   configuration_contract=case['original_contract'],
   parser_stdout_sha256=base.digest(root/'check-config.stdout'),
   parser_stderr_sha256=base.digest(root/'check-config.stderr'))
  return False
 if check['exit_code']!=0:return False
 literal_minimal_control(case,root,config,env,shared,result)
 if case['classification']=='file-capability' and not physical:result['capability_execution_pending']=True;return False
 if physical:
  result['physical_file_supplement']=dict(physical,staging_command=stage_file_source(case,root,current,shared))

 return True


def start_engine(case,engine,config,engine_port,current,handles,processes,helper,native_fd,fault_fd,fault_path,result):
 launch_start=time.monotonic_ns()
 service=base.start('engine',[engine,'--serve','--config',config,'--listen',f'127.0.0.1:{engine_port}'],current,handles,(native_fd,fault_fd));processes['engine']=(service,str(engine))
 try:helper.wait_for_tcp(engine_port,service,'real current native forwardAuth service')
 except Exception as error:
  result['engine_start_failure']={'type':type(error).__name__,'message':str(error)}
  result['engine_start_window']={'probe':case['probe_id'],'start_monotonic_ns':launch_start,
   'end_monotonic_ns':time.monotonic_ns(),'proxy_pid':service.pid,'observed_exit_code':service.poll(),
   'actual_fault_pids':sorted({row['pid'] for row in map(json.loads,fault_path.read_text().splitlines()) if 'pid' in row})}
  fault=case['fixture'].get('fault') or {}
  if fault.get('driver_kind')!='sink-open':raise

 return service


def cleanup_case(case,root,result,processes,shared,native_fd,fault_fd,handles,socket_path,observer_path):
 for label,(process,marker) in reversed(list(processes.items())):
  try:result['processes'][label]=shared.stop(label,process,marker)
  except Exception as error:result.setdefault('cleanup_errors',[]).append({'process':label,'type':type(error).__name__,'message':str(error)})
 os.close(native_fd);os.close(fault_fd)
 for handle in handles:handle.close()
 result['socket_removed']=not socket_path.exists();result['observer_socket_removed']=not observer_path.exists()
 result['provenance_socket_cleanup']={'path':str(root/PROVENANCE_SOCKET),
  'configured':acceptance_validate.provenance_mode(case),'removed':not (root/PROVENANCE_SOCKET).exists(),
  'monotonic_ns':time.monotonic_ns()}
 result['completed_ns']=time.monotonic_ns()


def literal_minimal_control(case,root,config,env,shared,result):
 if case['fixture'].get('explicit_source_correction',{}).get('literal_minimal_negative_control_required'):
  negative=config.with_name('unsupported-minimal.conf')
  negative.write_text(config.read_text().replace('phase4_mode=off','phase4_mode=minimal'))
  controller=shared.command('literal-minimal-config-controller',
   [PYTHON,'-P',FIXTURES/'acceptance_parser.py','--case-root',root,'--literal-minimal'],env)
  if controller['exit_code']!=0:raise RuntimeError('literal-minimal physical parser controller failed')
  result['literal_minimal_negative_config']=json.loads((root/'literal-minimal-check-config.command.json').read_text())


def probe_http_ready(case,root,env,host_port,deadline,history):
 for index in range(10):
  remaining=deadline-time.monotonic()
  if remaining<=0:break
  status,command,native=readiness_attempt(case,root,env,host_port,index,deadline,remaining,history)
  if readiness_success(status,command,native,deadline):return True
  if status!=404:break
  if time.monotonic()>=deadline:break
  time.sleep(max(0,min(0.1,deadline-time.monotonic())))
 return False


def readiness_success(status,command,native,deadline):
 return (status==200 and not command['timed_out'] and native is not None
  and native['positive_allocation_finish_free'] and time.monotonic()<deadline)


def measured_host_argv(case,root,helper,host,host_port,dynamic):
 trace=case['fixture'].get('syscall_observer')
 argv=host_argv(helper,host,host_port,dynamic,root)
 if trace:
  if trace['fixed_case']!=case['probe_id'] or trace['nonce']!=case['probe_id']:raise ValueError('fixed tracer case mismatch')
  argv=[TASK/'build/acceptance-syscalls','--auth-case',case['probe_id'],'--nonce',case['probe_id'],
   '--output',root/'host-syscalls.jsonl','--host-port',host_port,'--peer-port',0,'--seconds',trace['seconds']]
 return argv
