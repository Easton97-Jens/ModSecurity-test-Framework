"""Prepare full118 fixture inputs using an already reviewed central capture.

This never starts hosts or changes controller/admission code. The caller must
first stage the integrated product through the existing native prepare owner.
"""
from modsecurity_test_framework.connector_context import load_source
import argparse
import importlib.util
import json
import re
from pathlib import Path
import shutil

_helpers = load_source(Path(__file__).with_name('prepare.py'))
replace_once, save, seal, sha = _helpers.replace_once, _helpers.save, _helpers.seal, _helpers.sha
validate_output, validate_prepared_root = _helpers.validate_output, _helpers.validate_prepared_root

HERE = Path(__file__).parent
FILES = ('acceptance_driver.py', 'acceptance_backend.py', 'acceptance_client.py',
         'acceptance_proxy.py', 'acceptance_faults.c')


def instrument_private_toolchain(text):
    """Select only sealed Go inputs, with no admission environment extension."""
    root = _helpers.GO_NAMESPACE_ROOT
    text = replace_once(text, "    env = os.environ.copy()", """    if any(key.startswith('GO') for key in os.environ) or os.environ.get('PATH') != '/opt/controller:/usr/local/bin:/usr/bin:/usr/sbin:/bin':
        raise RuntimeError('unchanged controller environment required before private toolchain selection')
    env = os.environ.copy()""")
    text = replace_once(text, "GO='/usr/local/go/bin/go'",
        "GO=" + repr(root + '/bin/go') + ", GOROOT=" + repr(root) +
        ", PATH=" + repr(root + '/bin:/opt/controller:/usr/local/bin:/usr/bin:/usr/sbin:/bin') + ", GOENV='off', GOWORK='off'")
    text = replace_once(text, "['/usr/local/go/bin/go', 'version']", "[env['GO'], 'version']")
    guard = """    go_root = Path(env['GOROOT'])
    go_binary = Path(env['GO'])
    if go_root.resolve(strict=True) != go_root or go_binary.resolve(strict=True) != go_binary or (go_root / 'VERSION').is_symlink():
        raise RuntimeError('sealed physical private Go toolchain required')
    actual_go_sha256 = digest(go_binary)
    if actual_go_sha256 != GO_SHA256 or (go_root / 'VERSION').read_text().splitlines()[0:1] != ['go1.27.2']:
        raise RuntimeError('sealed private Go binary/VERSION identity differs')
    execute('go-toolchain-version', [env['GO'], 'version'], env)
    execute('go-toolchain-environment', [env['GO'], 'env', 'GOROOT', 'GOVERSION'], env)
    actual_version = (TASK / 'go-toolchain-version.stdout').read_text()
    actual_environment = (TASK / 'go-toolchain-environment.stdout').read_text().splitlines()
    if actual_version != 'go version go1.27.2 linux/amd64\\n' or actual_environment != [env['GOROOT'], 'go1.27.2']:
        raise RuntimeError('pinned private Go version/root mismatch before host admission')
    write('go-toolchain-binding.json', {'GO': env['GO'], 'GOROOT': env['GOROOT'],
        'GOTOOLCHAIN': env['GOTOOLCHAIN'], 'GOPROXY': env['GOPROXY'], 'GOSUMDB': env['GOSUMDB'],
        'GOENV': env['GOENV'], 'GOWORK': env['GOWORK'], 'actual_version': actual_version.strip(),
        'actual_go_env': actual_environment, 'go_sha256': actual_go_sha256,
        'VERSION_sha256': digest(go_root / 'VERSION'), 'verified_before_host_execution': True})
"""
    text = replace_once(text, "    rules = [", guard + "    rules = [")
    text = "GO_SHA256 = " + repr(_helpers.GO_SHA256) + '\n' + text
    if '/usr/local/go/bin/go' in text:
        raise ValueError('unpatched system Go reference')
    return text


def instrument_fault_hooks(text):
    additions = '\nextern int i12_acceptance_native_result(const char *, int);\nextern int i12_acceptance_fail_begin(void);\nextern void i12_acceptance_native_created(void *);\nextern void i12_acceptance_native_released(void *);\nextern int i12_acceptance_native_transaction_result(void *, const char *, int);\n'
    text = additions + text
    for name in ('msc_new_transaction', 'msc_new_transaction_with_id'):
        marker = 'Transaction *transaction = __real_' + name + '('
        if text.count(marker) != 1:
            raise ValueError('exact native constructor capture boundary unavailable: ' + name)
        text = text.replace(marker, 'Transaction *transaction = i12_acceptance_fail_begin() ? NULL : __real_' + name + '(', 1)
    text = replace_once(text, '    int extracted = 0;', '    int extracted = 0;\n    i12_acceptance_native_created(transaction);')
    text = replace_once(text, '    __real_msc_transaction_cleanup(transaction);', '    i12_acceptance_retained_body(transaction, "transaction_cleanup_before_free", 0);\n    i12_acceptance_retained_body(transaction, "transaction_cleanup_before_free", 1);\n    i12_acceptance_native_released(transaction);\n    __real_msc_transaction_cleanup(transaction);')
    marker = '    returned_subject("native_process_response_headers", call, &observed, result, 0, NULL);\n    return result;'
    text = replace_once(text, marker, '    returned_subject("native_process_response_headers", call, &observed, result, 0, NULL);\n    return i12_acceptance_native_transaction_result(transaction, "process_response_headers", result);')
    continuation = chr(92) + chr(10)
    marker = '    returned("native_process_request_headers", call, transaction, 1, 1, result, 0);\n    return result;'
    text = replace_once(text, marker, '    returned("native_process_request_headers", call, transaction, 1, 1, result, 0);\n    return i12_acceptance_native_transaction_result(transaction, "process_request_headers", result);')
    marker = '    returned("native_" #suffix, call, transaction, 1, phase, result, 0); return result; ' + continuation
    text = replace_once(text, marker, '    returned("native_" #suffix, call, transaction, 1, phase, result, 0); return i12_acceptance_native_transaction_result(transaction, #suffix, result); ' + continuation)
    marker = '    returned_subject("native_append_" #direction "_body", call, &observed, result, 0, NULL); ' + continuation + '    return result; ' + continuation
    text = replace_once(text, marker, '    returned_subject("native_append_" #direction "_body", call, &observed, result, 0, NULL); ' + continuation + '    return i12_acceptance_native_transaction_result(transaction, "append_" #direction "_body", result); ' + continuation)
    # Extra public SDK accessors run synchronously before this wrapper returns,
    # while its actual transaction is still alive. Retention is not inspection.
    retained = r'''static void i12_acceptance_retained_body(Transaction *transaction, const char *method, int response) {
    int saved = errno;
    const char *value = getenv("I12_ACCEPTANCE_FAULT_FD");
    char *end = NULL;
    if (value == NULL || *value == '\0' || transaction == NULL) return;
    long fd = strtol(value, &end, 10);
    if (*end != '\0' || fd < 3 || fd > 1024) { errno = saved; return; }
    pthread_mutex_lock(&lock);
    const struct mapping *entry = lookup(transaction, 1);
    if (entry != NULL && entry->allocation_scope_call != 0U) {
        size_t retained = response ? msc_get_response_body_length(transaction) : msc_get_request_body_length(transaction);
        struct timespec now;
        char line[512];
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            pthread_mutex_unlock(&lock);
            errno = saved;
            return;  /* Missing physical timestamp is missing evidence. */
        }
        int length = snprintf(line, sizeof(line),
            "{\"operation\":\"native_retained_body\",\"native_method\":\"%s\","
            "\"accessor\":\"msc_get_%s_body_length\",\"retained_body_bytes\":%zu,"
            "\"allocation_scope_call\":%" PRIu64 ",\"pid\":%ld,\"monotonic_ns\":%lld,\"injected\":false}\n",
            method, response ? "response" : "request", retained, entry->allocation_scope_call,
            (long)getpid(), (long long)now.tv_sec * 1000000000LL + now.tv_nsec);
        if (length > 0 && (size_t)length < sizeof(line)) (void)write((int)fd, line, (size_t)length);
    }
    pthread_mutex_unlock(&lock);
    errno = saved;
}
'''
    text = replace_once(text, '#define NATIVE_WRAPPER(suffix, phase)', retained + '\n#define NATIVE_WRAPPER(suffix, phase)')
    marker = '    int result = __real_msc_##suffix(transaction); ' + continuation
    extra = ('    if (strcmp(#suffix, "process_request_body") == 0) i12_acceptance_retained_body(transaction, #suffix, 0); ' + continuation +
             '    if (strcmp(#suffix, "process_response_body") == 0) i12_acceptance_retained_body(transaction, #suffix, 1); ' + continuation)
    text = replace_once(text, marker, marker + extra)
    marker = '    int result = __real_msc_append_##direction##_body(transaction, data, size); ' + continuation
    text = replace_once(text, marker, marker + '    i12_acceptance_retained_body(transaction, "append_" #direction "_body", strcmp(#direction, "response") == 0); ' + continuation)
    return text


def instrument_native_begin(text):
    declaration = '\nextern const msconnector_request *i12_acceptance_native_request(const msconnector_request *, msconnector_request *);\nextern void i12_acceptance_native_begin_result(const msconnector_request *, int);\n'
    marker = 'static int traefik_engine_handle_begin(traefik_engine_session *session,'
    text = replace_once(text, marker, declaration + marker)
    marker = '    success = msconnector_runtime_transaction_begin_request_stream(service->runtime,\n        &input.request, input.host_request_id, &session->transaction, decision,\n        &error);'
    replacement = '    msconnector_request fault_request;\n    const msconnector_request *selected_request = i12_acceptance_native_request(&input.request, &fault_request);\n    success = msconnector_runtime_transaction_begin_request_stream(service->runtime,\n        selected_request, input.host_request_id, &session->transaction, decision,\n        &error);\n    i12_acceptance_native_begin_result(selected_request, success);'
    return replace_once(text, marker, replacement)


LEDGER_SUFFIX = '-ledger.json'


GENERATED_CASE_KEY = '004-b044cc412aca'


def instrument_host_observer(text, manifest):
    before = 'transactionID != "tf-eos-target-53b4c671" && transactionID != "tf-eos-neighbor-8f217a3c"'
    allowed = [value for case in manifest['cases'] + manifest.get('supplementary_executions', []) for value in
        (case['transaction_id'], case['neighbor_id'], case['positive_control_id'],
         case['main_before_id'], case['main_after_id'], *case.get('sequence_ids', []))]
    generated = [case for case in manifest['cases'] if case['fixture']['request'].get('omit_transaction_id')]
    if len(generated) != 1 or generated[0]['key'] != GENERATED_CASE_KEY or not generated[0]['id'].endswith('::transaction_id_generated_or_fallback'):
        raise ValueError('Only exact reviewed original generated-ID case may admit empty host metadata')
    selected = set(manifest.get('selected_keys', [case['key'] for case in manifest['cases']]))
    allowed += [value for case in manifest['cases'] + manifest.get('supplementary_executions', [])
                if case['key'] in selected for value in case.get('readiness_ids', [])]
    after = ' && '.join('transactionID != ' + json.dumps(value) for value in allowed)
    after += ' && !(transactionID == "" && os.Getenv("I12_NATIVE_GENERATED_CASE") == "' + GENERATED_CASE_KEY + '")'
    return replace_once(text, before, after), allowed


def prepare(root, manifest_path, stage_name="acceptance"):
    if re.fullmatch(r"acceptance(?:-v[1-9]\d*)?", stage_name) is None:
        raise ValueError("explicit acceptance stage name required")
    root = validate_prepared_root(root)
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('original_id_count') != 118 or len(manifest.get('cases', [])) != 118:
        raise ValueError('complete original118 manifest required')
    source, fixtures = root / ('source-' + stage_name), root / ('fixtures-' + stage_name)
    spec_path = root / ('admission-' + stage_name + '.json')
    for path in (source, fixtures, spec_path, root / ('source-' + stage_name + LEDGER_SUFFIX), root / ('fixtures-' + stage_name + LEDGER_SUFFIX)):
        validate_output(path, fresh=True)
    shutil.copytree(root / 'source', source)
    shutil.copytree(root / 'fixtures', fixtures)
    for tree in (source, fixtures):
        for path in (tree, *tree.rglob('*')):
            path.chmod(0o700 if path.is_dir() or path.stat().st_mode & 0o111 else 0o600)
    # Capture profile remains central traefik-native. This is only an explicit
    # synthetic nonce allowlist expansion in a disposable source tree.
    instrument_source(source, fixtures, manifest)
    for name in FILES:
        shutil.copyfile(HERE / name, fixtures / name)
    # Complete File4 input tree is sealed by the same fixtures ledger. Actual
    # reader-owned copies are made afresh under /task for each execution.
    trace_cases = stage_file_fixtures(fixtures, manifest)
    # Reuse the currently reviewed transport path guards, never a second guard.
    shutil.copyfile(HERE / 'fault_proxy.py', fixtures / 'fault_proxy.py')
    shutil.copyfile(manifest_path, fixtures / 'acceptance-manifest.json')
    stage_driver(fixtures, trace_cases)
    save(fixtures / 'acceptance-producer-binding.json', {'manifest_path': str(manifest_path),
        'manifest_sha256': sha(manifest_path), 'producer_inputs': {name: sha(HERE / name) for name in FILES},
        'runtime_qualified': False})
    admission = json.loads((root / 'admission.json').read_text())
    admission['timeout_seconds'] = 1800  # Existing controller maximum; never relax it.
    for name, tree, target in (('source', source, '/mnt/src'), ('fixtures', fixtures, '/mnt/fixtures')):
        ledger = root / (name + '-' + stage_name + LEDGER_SUFFIX)
        save(ledger, seal(tree))
        ledger.chmod(0o444)
        binding = next(item for item in admission['bindings'] if item['target'] == target)
        binding.update(source=str(tree), ledger=str(ledger), ledger_sha256=sha(ledger))
    save(spec_path, admission)
    spec_path.chmod(0o444)
    return {'admission': str(spec_path), 'sha256': sha(spec_path), 'runtime_qualified': False}


def instrument_source(source, fixtures, manifest):
    observer = source / 'connectors/traefik/native_middleware/i12_observer.go'
    baseline = sha(observer)
    observer_text, allowed = instrument_host_observer(observer.read_text(), manifest)
    observer.write_text(observer_text)
    c_observer = source / 'ci/runtime/lifecycle/native-lifecycle-observer.c'
    native_baseline = sha(c_observer)
    original_native = c_observer.read_text()
    c_observer.write_text(instrument_fault_hooks(original_native))
    native_service = source / 'connectors/traefik/src/traefik_engine_service.c'
    native_service_before = native_service.read_text()
    native_service.write_text(instrument_native_begin(native_service_before))
    save(source / 'acceptance-capture-delta.json', {'profile': 'traefik-native',
        'observer_before_sha256': baseline, 'observer_after_sha256': sha(observer),
        'allowed_exact_transaction_ids': allowed, 'native_before_sha256': native_baseline,
        'native_after_sha256': sha(c_observer), 'native_fault_hooks': 'constructorNULL/invalidheaderreturn/loggingfailure only with explicit test env',
        'native_service_before_sha256': __import__('hashlib').sha256(native_service_before.encode()).hexdigest(),
        'native_service_after_sha256': sha(native_service), 'production_behavior_changes': False})
    (fixtures / 'native-observer-before.c').write_text(original_native)


def stage_file_fixtures(fixtures, manifest):
    harness = HERE.parents[1]
    shutil.copytree(harness / 'i12_file', fixtures / 'i12_file',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copytree(harness / 'fixtures/i12-file-source', fixtures / 'i12-file-source')
    for tree in (fixtures / 'i12_file', fixtures / 'i12-file-source'):
        for path in (tree, *tree.rglob('*')):
            path.chmod(0o700 if path.is_dir() else 0o600)
    selected_keys = set(manifest.get('selected_keys', [case['key'] for case in manifest['cases']]))
    trace_cases = [case for case in manifest['cases'] + manifest.get('supplementary_executions', [])
                   if case['key'] in selected_keys and case['fixture'].get('syscall_observer')]
    if trace_cases:
        shutil.copyfile(HERE / 'acceptance_syscalls.c', fixtures / 'acceptance_syscalls.c')
    return trace_cases


def stage_driver(fixtures, trace_cases):
    driver_path = fixtures / 'driver.py'
    text = driver_path.read_text()
    cutoff = text.index("    write('current-product-binding.json'")
    text = text[:cutoff]
    text = instrument_private_toolchain(text)
    marker = "    execute('engine-build', [SOURCE / 'connectors/traefik/build/build-engine-service.sh', 'build'], env)"
    compile_faults = "    fault_object = TASK / 'build/acceptance-faults.o'\n" + \
        "    execute('acceptance-faults-compile', ['/usr/bin/gcc', '-std=c17', '-Wall', '-Wextra', '-Werror', '-pthread', '-I', SOURCE / 'common/include', '-c', FIXTURES / 'acceptance_faults.c', '-o', fault_object], env)\n" + \
        "    env['TRAEFIK_ENGINE_SERVICE_LDFLAGS'] += ' ' + str(fault_object) + ' ' + ' '.join('-Wl,--wrap=' + symbol for symbol in ('openat', 'setvbuf', 'fputs', 'fflush', 'fclose', 'msconnector_generic_map_request'))\n"
    if trace_cases:
        compile_faults += "    execute('acceptance-syscalls-compile', ['/usr/bin/gcc', '-std=c17', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', FIXTURES / 'acceptance_syscalls.c', '-o', TASK / 'build/acceptance-syscalls'], env)\n"
    text = replace_once(text, marker, compile_faults + marker)
    text += "    write('current-product-binding.json', json.loads((FIXTURES / 'current-product-binding.json').read_text()))\n"
    text += "    write('acceptance-build.json', {'host_sha256': digest(host), 'engine_sha256': digest(engine), 'observer_object_sha256': digest(observer), 'sdk_accessor_object_sha256': digest(accessor), 'wrap_symbols': SYMBOLS, 'fault_symbols': ('openat', 'setvbuf', 'fputs', 'fflush', 'fclose', 'msconnector_generic_map_request'), 'native_observer_sha256': digest(SOURCE / 'ci/runtime/lifecycle/native-lifecycle-observer.c'), 'fault_helper_sha256': digest(FIXTURES / 'acceptance_faults.c'), 'manifest_sha256': digest(FIXTURES / 'acceptance-manifest.json'), 'source_inputs': {str(path.relative_to(SOURCE)): digest(path) for path in sorted((SOURCE / 'common/src').glob('*.c')) + sorted((SOURCE / 'common/runtime').glob('*.c')) + [SOURCE / 'connectors/profile_registry.c', SOURCE / 'connectors/traefik/src/traefik_engine_service.c', SOURCE / 'ci/runtime/lifecycle/native-lifecycle-observer.c', SOURCE / 'ci/runtime/lifecycle/native-lifecycle-sdk.cpp']}})\n"
    text += "    write('unused-baseline-socket-cleanup.json', {'removed': helper.remove_private_engine_socket_dir(socket_dir, inputs.engine_socket_parent)})\n"
    text += "    acceptance_spec = importlib.util.spec_from_file_location('acceptance_driver', FIXTURES / 'acceptance_driver.py')\n"
    text += "    acceptance_driver = importlib.util.module_from_spec(acceptance_spec)\n    acceptance_spec.loader.exec_module(acceptance_driver)\n"
    text += "    acceptance_driver.run(helper, inputs, artifacts, engine, host, env)\n"
    (fixtures / 'base_driver.py').write_text(text)
    driver_path.write_text("import importlib.util, sys\nfrom pathlib import Path\n"
        "spec = importlib.util.spec_from_file_location('base_driver', Path('/mnt/fixtures/base_driver.py'))\n"
        "base_driver = importlib.util.module_from_spec(spec)\nsys.modules['base_driver'] = base_driver\n"
        "spec.loader.exec_module(base_driver)\nbase_driver.main()\n")
    for name in ('base_driver.py', 'driver.py', *FILES):
        if name.endswith('.py'):
            compile((fixtures / name).read_text(), name, 'exec')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--stage-name', default='acceptance')
    args = parser.parse_args()
    print(json.dumps(prepare(args.root, args.manifest, args.stage_name)))
