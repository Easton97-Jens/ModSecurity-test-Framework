"""Extend an immutable existing Stock capture link recipe with private probes."""
import argparse
import json
from pathlib import Path
import subprocess

from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.stock_qualification import EXTERNAL, PREVIOUS, REPO, read_text, regular, sha, storage_root

CXX_LINK_FLAG = '-lstdc++'
RECEIPT_FILE = 'receipt.json'
CAPTURE_SOURCE = 'capture-04/source'


# This is the grammar emitted by stock_capture.prepare, before private probes.
# The saved JSON supplies operands, never authority to select programs or flags.
STRICT_FLAGS = ['-std=c17', '-Wall', '-Wextra', '-Werror', '-fPIC', '-fno-lto', '-pthread']
INCLUDE_DIRS = ('', 'common/include', 'common/runtime', 'ci/runtime/lifecycle',
                'connectors/lighttpd/stock_sidecar')
WRAPPED_SYMBOLS = frozenset((
    'msc_append_request_body', 'msc_append_response_body', 'msc_intervention',
    'msc_new_transaction', 'msc_new_transaction_with_id', 'msc_process_logging',
    'msc_process_request_body', 'msc_process_request_headers',
    'msc_process_response_body', 'msc_process_response_headers', 'msc_transaction_cleanup',
    'msconnector_runtime_response_companion_claim_handle',
    'msconnector_runtime_response_companion_handoff_with_handle',
    'msconnector_runtime_response_companion_revoke_handle',
    *('msconnector_runtime_response_companion_session_' + name for name in (
        'append_response_body_chunk', 'cancel', 'fail', 'finish_response_body',
        'process_response_headers', 'record_host_action', 'release', 'set_response_commit_state')),
    *('msconnector_runtime_transaction_' + name for name in (
        'append_request_body_chunk', 'append_response_body_chunk', 'begin', 'begin_request_stream',
        'destroy', 'finalize_and_snapshot', 'finish', 'finish_request_body',
        'finish_response_body', 'process_response_headers')),
    *('msconnector_transaction_contract_' + name for name in (
        'cleanup', 'complete_phase', 'finish', 'init', 'record_response_metadata',
        'set_response_committed')),
))


def validated_recipe(argv, old):
    """Recognize the retained compiler recipe before applying known substitutions."""
    if not isinstance(argv, list) or not all(isinstance(value, str) for value in argv):
        raise ValueError('invalid retained compiler recipe argv')
    source, build = old / CAPTURE_SOURCE, old / 'capture-04/build'
    prefix = ['rtk', 'proxy', 'cc', *STRICT_FLAGS]
    for relative in INCLUDE_DIRS:
        prefix += ['-I', str(source / relative)]
    prefix += ['-DMSCONNECTOR_STOCK_SIDECAR_MAIN',
               str(source / 'connectors/lighttpd/stock_sidecar/stock_sidecar.c'),
               str(source / 'common/runtime/msconnector_runtime.c'),
               str(source / 'connectors/profile_registry.c')]
    suffix = [str(build / (name + '.o')) for name in ('observer', 'host', 'bootstrap', 'sdk')]
    suffix += ['-Wl,--wrap=' + name for name in sorted(WRAPPED_SYMBOLS)]
    suffix += [CXX_LINK_FLAG, '-lmodsecurity', '-lcrypto', '-lyajl', '-o',
               str(build / 'lighttpd-stock-sidecar')]
    if argv[:len(prefix)] != prefix or argv[-len(suffix):] != suffix:
        raise ValueError('retained compiler recipe differs from stock_capture grammar')
    common = argv[len(prefix):-len(suffix)]
    # Only the generator's Common translation units can occupy the variable span.
    expected_common = [str(source / 'common/src' / path.name)
                       for path in sorted((REPO / 'common/src').glob('*.c'))]
    if not common or common != expected_common:
        raise ValueError('retained compiler recipe has unexpected Common inputs')
    return list(argv)


def _validate_include_directories(argv):
    for index, value in enumerate(argv[:-1]):
        if value != '-I':
            continue
        path = Path(argv[index + 1])
        if ('..' in path.parts or not path.is_relative_to(EXTERNAL)
                or any(part.is_symlink() for part in (*path.parents, path))
                or not path.is_dir()):
            raise ValueError('compiler include directory must be physical external source')


def _source_arguments(argv, source_copy, old):
    if source_copy is None:
        return argv
    source_copy = source_copy.absolute()
    if not source_copy.is_relative_to(EXTERNAL) or '..' in source_copy.parts:
        raise ValueError('source snapshot must be external')
    return [value.replace(str(old / CAPTURE_SOURCE), str(source_copy)) for value in argv]


def build(output, mime_build, sink_faults=None, source_copy=None, helper_build=None, transport_observer=None):
    storage_root(EXTERNAL)
    output = output.absolute()
    if '..' in output.parts or not output.is_relative_to(EXTERNAL):
        raise ValueError('external task output required')
    if any(path.is_symlink() for path in (*output.parents, output)):
        raise ValueError('output aliases forbidden')
    output.mkdir(mode=0o700, parents=True)
    old = PREVIOUS / 'stock'
    recipe = regular(old / 'capture-04/compile-sidecar.command.json')
    argv = validated_recipe(json.loads(read_text(recipe))['argv'], old)
    substitutions = {
        str(old / 'capture-04/build/observer.o'): str(regular(mime_build / 'native-observer.o')),
        str(old / 'capture-04/build/host.o'): str(regular(old / 'nonroot-input/host.o')),
        str(old / 'capture-04/build/lighttpd-stock-sidecar'): str(output / 'lighttpd-stock-sidecar')}
    if helper_build is not None:
        for name in ('host', 'sdk', 'bootstrap'):
            substitutions[str(old / 'capture-04/build' / (name + '.o'))] = str(regular(helper_build / (name + '.o')))
    argv = [substitutions.get(value, value) for value in argv]
    source_copy = source_copy.absolute() if source_copy is not None else None
    argv = _source_arguments(argv, source_copy, old)
    argv.insert(argv.index(CXX_LINK_FLAG), str(regular(mime_build / 'mime-accessor.o')))
    if sink_faults is not None:
        argv.insert(argv.index(CXX_LINK_FLAG), str(regular(sink_faults)))
        argv += ['-Wl,--wrap=' + name for name in ('fdopen', 'fputs', 'fflush', 'fclose', 'accept')]
    if transport_observer is not None:
        argv.insert(argv.index(CXX_LINK_FLAG), str(regular(transport_observer)))
        argv += ['-Wl,--wrap=send', '-Wl,--wrap=recv']
    _validate_include_directories(argv)
    inputs = {value: sha(regular(value)) for value in argv if value.endswith(('.c', '.o'))}
    source_root = source_copy if source_copy is not None else old / CAPTURE_SOURCE
    headers = {str(path): sha(regular(path)) for path in source_root.rglob('*.h')}
    receipt = {'argv': argv, 'compile_recipe': {'path': str(recipe), 'sha256': sha(recipe)},
        'actual_mime_collector_build': {'path': str(mime_build / RECEIPT_FILE),
            'sha256': sha(regular(mime_build / RECEIPT_FILE))},
        'actual_compilation_inputs': inputs, 'actual_snapshot_header_inputs': headers, 'product_changes': False,
        'probe_scope': 'Existing capture observer with typed actual SDK scalars; optional exact private event FILE fault injection.',
        'full_lifecycle_qualified': False}
    if source_copy is not None and (source_copy.parent / 'stock-specific-rebase-receipt.json').is_file():
        rebase = regular(source_copy.parent / 'stock-specific-rebase-receipt.json')
        receipt['actual_stock_source_rebase'] = {'path': str(rebase), 'sha256': sha(rebase)}
    result = subprocess.run(argv, capture_output=True, timeout=180)
    (output / 'compile.stdout').write_bytes(result.stdout)
    (output / 'compile.stderr').write_bytes(result.stderr)
    receipt['exit'] = result.returncode
    if result.returncode == 0:
        receipt['binary_sha256'] = sha(output / 'lighttpd-stock-sidecar')
    (output / RECEIPT_FILE).write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mime-build', type=Path, required=True)
    parser.add_argument('--sink-faults', type=Path)
    parser.add_argument('--source-copy', type=Path)
    parser.add_argument('--helper-build', type=Path)
    parser.add_argument('--transport-observer', type=Path)
    args = parser.parse_args()
    result = build(args.output, args.mime_build, args.sink_faults, args.source_copy, args.helper_build, args.transport_observer)
    print(json.dumps({'exit': result['exit'], 'binary_sha256': result.get('binary_sha256')}))
    raise SystemExit(result['exit'])
