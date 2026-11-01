"""Retake with an explicit expanded synthetic-ID observer allowlist.

The central observer deliberately admits only two historical IDs. Keep those
bytes intact and bind the test-only expansion in a separate disposable copy.
"""
import json
from pathlib import Path
import shutil
import sys

from connector_suite.adapters.traefik.harness.i12.native.prepare import replace_once, save, seal, sha, validate_output, validate_prepared_root


def prepare_scope(root):
    root = validate_prepared_root(root)
    source = root / 'source-host-v2'
    for output in (source, root / 'source-host-v2-ledger.json',
                   *(root / ('admission-' + mode + '-host-v2.json') for mode in ('initial', 'faults-v3', 'mime'))):
        validate_output(output, fresh=True)
    shutil.copytree(root / 'source', source)
    for path in (source, *source.rglob('*')):
        path.chmod(0o700 if path.is_dir() or path.stat().st_mode & 0o111 else 0o600)
    observer = source / 'connectors/traefik/native_middleware/i12_observer.go'
    baseline = sha(observer)
    labels = ('allow-chunks', 'p1-deny', 'p2-deny', 'p3-deny', 'p4-safe-late', 'mime-out', 'neighbor',
              'fault-mse1', 'fault-result', 'fault-postcommit', 'fault-ack', 'client-cancel',
              'request-type-missing', 'request-charset-missing', 'request-charset-iso',
              'response-type-missing', 'response-charset-missing', 'response-charset-iso')
    before = 'transactionID != "tf-eos-target-53b4c671" && transactionID != "tf-eos-neighbor-8f217a3c"'
    after = ' && '.join('transactionID != ' + json.dumps('tf-' + label) for label in labels)
    observer.write_text(replace_once(observer.read_text(), before, after))
    save(source / 'i12-host-scope-binding.json', {'capture_profile': 'traefik-native', 'central_observer_sha256': baseline,
         'expanded_observer_sha256': sha(observer), 'allowed_synthetic_transaction_ids': ['tf-' + label for label in labels],
         'delta_scope': 'observer ID allowlist only; no product decision or transport behavior changed'})
    ledger = root / 'source-host-v2-ledger.json'
    save(ledger, seal(source))
    ledger.chmod(0o444)
    for mode in ('initial', 'faults-v3', 'mime'):
        path = root / ('admission.json' if mode == 'initial' else 'admission-' + mode + '.json')
        admission = json.loads(path.read_text())
        for binding in admission['bindings']:
            if binding['target'] == '/mnt/src':
                binding.update(source=str(source), ledger=str(ledger), ledger_sha256=sha(ledger))
        output = root / ('admission-' + mode + '-host-v2.json')
        save(output, admission)
        output.chmod(0o444)
        print(json.dumps({'spec': str(output), 'sha256': sha(output), 'runtime_qualified': False}))


if __name__ == '__main__':
    prepare_scope(Path(sys.argv[1]))
