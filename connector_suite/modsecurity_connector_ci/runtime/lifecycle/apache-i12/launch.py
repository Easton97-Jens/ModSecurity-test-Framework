"""One genuine nonroot Apache POST/allow plus separate GET neighbor capture."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import hashlib
import json
import os
from pathlib import Path
import sys

paths = load_tool('ci/runtime/lifecycle/apache-i12/paths.py')
capture_process = load_tool('ci/runtime/lifecycle/apache-i12/process_capture.py').capture_process
import shutil
import subprocess
import threading
import time

settings=json.loads(Path('/mnt/fixtures/settings.json').read_text())
os.environ['CODEX_TEMP_ROOT'] = settings['storage_root']
base=paths.private_directory(settings['runtime_root'])
owned=base/'native-bin/apache2';owned.parent.mkdir(mode=0o700)
shutil.copyfile('/usr/sbin/apache2',owned);owned.chmod(0o500)
assert owned.stat().st_uid==os.geteuid() and hashlib.sha256(owned.read_bytes()).hexdigest()=='32226a96ed9257837341b7909edae8da368922565f4662b1f76624e7c74e4a3d'
assert hashlib.sha256(Path('/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3.0.14').read_bytes()).hexdigest()=='32257230b8f378987ba1204049dcc1e23927fd44c8778e09d41805ad705c3407'
runtime_paths = {
    'APACHE_BUILD_ROOT': base / 'build', 'LOG_DIR': base / 'logs',
    'RESULTS_DIR': base / 'results', 'RUNTIME_ROOT': base / 'runtime',
    'RUNTIME_BASE': base / 'runtime-base', 'BUILD_ROOT': base, 'APACHE_CASE_OUTPUT_ROOT': base}
observer_files = {
    'NATIVE_OBSERVER': 'apache-native-api.jsonl',
    'HOST_OBSERVER': 'apache-host-eos.jsonl', 'BACKEND_CAPTURE': 'apache-backend.jsonl'}
env = dict(os.environ)
env.update({key: str(path) for key, path in runtime_paths.items()})
env.update({'MSCONNECTOR_APACHE_' + key: '/task/' + filename
            for key, filename in observer_files.items()})
env.update({
    'FRAMEWORK_ROOT': '/mnt/framework', 'HTTPD_PREFIX': '/usr/lib/apache2',
    'APACHE_HTTPD': str(owned), 'APACHE_MODULE': '/mnt/artifacts/apache/test-observed.so',
    'MODSECURITY_LIB_DIR': '/usr/lib/x86_64-linux-gnu', 'PYTHON': '/usr/local/bin/python3',
    'CURL': '/mnt/fixtures/observed-curl.py', 'RUN_ONE_CASE': '1',
    'TEST_CASE': str(paths.fixture_path(settings['fixture_relative_path'])),
    'FORCE_ALL_CASES': '1', 'PORT': '18140', 'CASE_SCOPE': 'all', 'MODSECURITY_TEST_VARIANT': 'no-crs',
    'MSCONNECTOR_LIFECYCLE_RUN': settings['run_id'], 'MSCONNECTOR_LIFECYCLE_PROFILE': 'apache-native',
    'MSCONNECTOR_LIFECYCLE_CASE': settings['case_id'], 'I12_APACHE_PRIVATE_RUNTIME': str(base),
    'I12_APACHE_SELECTED_URI': settings['selected_uri'], 'I12_APACHE_FOLLOWUP': '1',
    'I12_APACHE_CAPTURE_DELAY': '1'})
if settings.get('canonical_no_crs_baseline'):
    env['MODSECURITY_RULE_PREAMBLE_FILE']='/mnt/framework/tests/rules/no-crs-baseline.conf'
argv=['rtk','proxy','/bin/sh','/mnt/src/connectors/apache/harness/run_apache_smoke.sh']
stop=threading.Event();snapshots=[];errors=[]
state=base/'runtime/run/httpd-supervisor-state.json'
def snapshot_child():
    while not stop.is_set():
        try:
            if state.exists():
                lease=json.loads(state.read_text())
                snapshot = capture_process(lease['child_pid'], lease['child_pid_starttime'])
                snapshots.append(dict(snapshot, actual_lease=lease))
        except (FileNotFoundError,ProcessLookupError,json.JSONDecodeError):
            pass
        except Exception as error:
            errors.append({'type':type(error).__name__,'message':str(error)})
        stop.wait(0.05)
thread=threading.Thread(target=snapshot_child,daemon=True);thread.start()
started=time.monotonic_ns()
result=None
timed_out=False
execution_error=None
try:
    with Path('/task/apache.stdout').open('xb') as stdout,Path('/task/apache.stderr').open('xb') as stderr:
        result=subprocess.run(argv,env=env,stdout=stdout,stderr=stderr,timeout=240)
except subprocess.TimeoutExpired as error:
    timed_out=True
    execution_error={'type':type(error).__name__,'message':str(error)}
except Exception as error:
    execution_error={'type':type(error).__name__,'message':str(error)}
finally:
    stop.set();thread.join(timeout=5)
receipt={'argv':argv,'actual_driver_exit':result.returncode if result is not None else None,'timed_out':timed_out,'execution_error':execution_error,'started_monotonic_ns':started,
    'completed_monotonic_ns':time.monotonic_ns(),'environment_overrides':{key:value for key,value in env.items() if os.environ.get(key)!=value},
    'owned_binary':{'path':str(owned),'uid':owned.stat().st_uid,'mode':oct(owned.stat().st_mode&0o777),'sha256':hashlib.sha256(owned.read_bytes()).hexdigest()},
    'native_process_snapshots':snapshots,'native_process_sampler_errors':errors,'sampler_thread_stopped':not thread.is_alive(),
    'source_instrumentation_is_test_only':True,'original_selected_id':settings['original_selected_id'],'settings':settings,
    'original_null_oracles_preserved_elsewhere':True,'one_main_and_one_separate_neighbor':True,
    'full_lifecycle_qualification':None}
with Path('/task/apache-lifecycle-command.json').open('w', encoding='utf-8') as receipt_stream:
    json.dump(receipt, receipt_stream, indent=2, sort_keys=True)
    receipt_stream.write('\n')
print(json.dumps({'actual_driver_exit':result.returncode if result is not None else None,'timed_out':timed_out,'execution_error':execution_error,'native_process_snapshots':len(snapshots),'sampler_errors':len(errors),'full_lifecycle_qualification':None}))
if timed_out:
    exit_code = 124
elif result is not None:
    exit_code = result.returncode
else:
    exit_code = 1
raise SystemExit(exit_code)
