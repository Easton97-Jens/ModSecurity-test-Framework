"""Verify every source byte against the retained Git archive and capture receipt."""
import copy
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

ADAPTER_CONTRACT = 'i12.envoy.preserve-a622-observer.v1'
MANIFEST = 'ci/runtime/lifecycle/i12/manifest.json'
E4_REVISION = 'e4c872cde16eb73182de49c09a8ba8ee4219b417'
E4_MANIFEST = 'b4200031b7fd353e29e9980345dbe9de38990439ba886164aa410b00439b5cd8'
E4_RUNTIME = 'common/runtime/msconnector_runtime.c'
E4_STALE = '0fa85f5658be96a25204adf489b2e18149a5f826b5ed528e55ec7b2ffe410aa4'
E4_CURRENT = 'ad6ebda89b5e9efd13c845ce8bb76f25a842dde9e3100b486af94f987e3ad301'
AFAF_MANIFEST = '1ff2244e87d6d62fb6f6d8c3b41e81e897ba36c4c9373b12c1aabb994ecc1f85'
HISTORICAL_REPOSITORY_OBJECTS = {
    E4_STALE: E4_RUNTIME,
    '7f1544f1f36042c68359c7caed7d5dc4ce8cc77d44282debdc3955ea725a5e9c':
        'common/runtime/http_authorization_service.c',
    '445dcfd6c296c442d8b1593e4bc1106077900b0c745cf1b79beb0d3ead555580':
        'connectors/traefik/response_observer/observer.go',
}
E4_INVERSE = (
    '--- a/payload\n'
    '+++ b/payload\n'
    '@@ -152,7 +152,6 @@\n'
    '     int request_decision_pending;\n'
    '     msconnector_decision pending_response_decision;\n'
    '     int response_decision_pending;\n'
    '-    int request_partial_observed;\n'
    ' } msconnector_native_transaction;\n'
    ' \n'
    ' typedef struct msconnector_runtime_event_metadata {\n'
    '@@ -313,24 +312,6 @@\n'
    '     runtime_operation_lock(runtime);\n'
    '     appended = msconnector_modsecurity_append_request_body(\n'
    '         &transaction->modsecurity, data, append_size, error);\n'
    '-    if (appended) {\n'
    '-        msconnector_native_transaction *native = transaction->modsecurity.native_transaction;\n'
    '-        const size_t retained = msc_get_request_body_length(native->transaction);\n'
    '-        if (retained > transaction->request_body.bytes_seen) {\n'
    '-            (void)msconnector_transaction_contract_fail(&transaction->contract,\n'
    '-                MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR, transaction_now_ms());\n'
    '-            transaction->contract.error_phase = MSCONNECTOR_PHASE_REQUEST_BODY;\n'
    '-            transaction->request_blocked = 1;\n'
    '-            appended = runtime_error(error, MSCONNECTOR_ERROR_MODSECURITY_FAILURE,\n'
    '-                "native request body length exceeds offered bytes", "libmodsecurity");\n'
    '-        } else {\n'
    '-            transaction->request_body.bytes_retained = retained;\n'
    '-            transaction->request_body.truncated = retained < transaction->request_body.bytes_seen;\n'
    '-            if (native->request_partial_observed) {\n'
    '-                transaction->request_body.limit_outcome = MSCONNECTOR_BODY_LIMIT_OUTCOME_PROCESS_PARTIAL;\n'
    '-            }\n'
    '-        }\n'
    '-    }\n'
    '     runtime_operation_unlock(runtime);\n'
    '     return appended;\n'
    ' }\n'
    '@@ -1267,13 +1248,12 @@\n'
    '     msconnector_error *error) {\n'
    '     msconnector_native_transaction *native = native_transaction;\n'
    '     msconnector_runtime *runtime = userdata;\n'
    '-    int appended = 1;\n'
    '-    if (size > 0U && !msconnector_native_body_append_can_continue(\n'
    '-            appended = msc_append_request_body(native->transaction, data, size))) {\n'
    '+    if (size > 0U &&\n'
    '+        !msconnector_native_body_append_can_continue(\n'
    '+            msc_append_request_body(native->transaction, data, size))) {\n'
    '         return runtime_error(error, MSCONNECTOR_ERROR_MODSECURITY_FAILURE,\n'
    '             "request body append failed", "libmodsecurity");\n'
    '     }\n'
    '-    native->request_partial_observed |= appended == 0;\n'
    '     if (!native->request_decision_pending) {\n'
    '         if (!native_decision(runtime, native, MSCONNECTOR_PHASE_REQUEST_BODY,\n'
    '                 &native->pending_request_decision, error)) return 0;\n'
    '@@ -1819,8 +1799,7 @@\n'
    '     if (decision->phase == MSCONNECTOR_PHASE_REQUEST_BODY) {\n'
    '         event->body.bytes_seen = transaction->request_body.bytes_seen;\n'
    '         event->body.bytes_inspected = transaction->request_body.bytes_inspected;\n'
    '-        event->body.limit_outcome = msconnector_body_limit_outcome_name(\n'
    '-            transaction->request_body.limit_outcome);\n'
    '+        event->body.limit_outcome = msconnector_decision_is_body_limit(decision) ? "reject" : "";\n'
    '         event->flags.body_truncated = transaction->request_body.truncated;\n'
    '         return;\n'
    '     }\n'
    '@@ -1981,26 +1960,10 @@\n'
    '         return replay_event_write_failure(transaction, error);\n'
    '     }\n'
    '     runtime = transaction->runtime;\n'
    '-    if (runtime->event_file == NULL) {\n'
    '-        return 1;\n'
    '-    }\n'
    '-    if (!msconnector_decision_to_event(decision, &event, runtime->connector_name,\n'
    '+    if (runtime->event_file == NULL ||\n'
    '+        !msconnector_decision_to_event(decision, &event, runtime->connector_name,\n'
    '             transaction->metadata.transaction_id)) {\n'
    '-        if (decision->phase != MSCONNECTOR_PHASE_REQUEST_BODY ||\n'
    '-            transaction->request_body.limit_outcome !=\n'
    '-                MSCONNECTOR_BODY_LIMIT_OUTCOME_PROCESS_PARTIAL) {\n'
    '-            return 1;\n'
    '-        }\n'
    '-        msconnector_event_init(&event);\n'
    '-        event.meta.connector = runtime->connector_name;\n'
    '-        event.meta.transaction_id = transaction->metadata.transaction_id;\n'
    '-        event.meta.message_id = MSCONN_EVENT_BODY_LIMIT;\n'
    '-        event.meta.message = msconnector_event_default_message(event.meta.message_id);\n'
    '-        event.meta.level = msconnector_event_default_level(event.meta.message_id);\n'
    '-        event.decision.phase = MSCONNECTOR_PHASE_REQUEST_BODY;\n'
    '-        event.decision.status = MSCONNECTOR_STATUS_OK;\n'
    '-        event.decision.action = "allow";\n'
    '-        event.decision.requested_action = "allow";\n'
    '+        return 1;\n'
    '     }\n'
    '     runtime_operation_lock(runtime);\n'
    '     timestamp_now(timestamp, sizeof(timestamp));\n'
    '@@ -2618,6 +2581,10 @@\n'
    '         !append_request_body_to_engine(transaction, data, append_size, error)) {\n'
    '         return 0;\n'
    '     }\n'
    '+    if (append_size > 0U && runtime->config.enable == MSCONNECTOR_BOOL_ON &&\n'
    '+        !transaction->request_blocked) {\n'
    '+        transaction->request_body.bytes_inspected += append_size;\n'
    '+    }\n'
    '     return 1;\n'
    ' }\n'
    ' \n'
    '@@ -2656,17 +2623,9 @@\n'
    '         return 0;\n'
    '     }\n'
    '     transaction->request_body.finished = 1;\n'
    '-    if (msconnector_decision_is_body_limit(decision)) {\n'
    '-        transaction->request_body.limit_outcome = MSCONNECTOR_BODY_LIMIT_OUTCOME_REJECT;\n'
    '-    }\n'
    '     if (!mark_flow(transaction, MSCONNECTOR_PHASE_REQUEST_BODY, error)) {\n'
    '         return 0;\n'
    '     }\n'
    '-    if (!msconnector_decision_action_is_disruptive(\n'
    '-            msconnector_decision_action_from_decision(decision)) &&\n'
    '-        transaction->request_body.limit_outcome == MSCONNECTOR_BODY_LIMIT_OUTCOME_PROCESS_PARTIAL) {\n'
    '-        if (!emit_decision_event(transaction, decision, NULL, error)) return 0;\n'
    '-    }\n'
    '     return handle_decision(transaction, decision, error, &terminal);\n'
    ' }\n'
    ' \n'
    '@@ -4282,7 +4241,6 @@\n'
    '         progress->truncated = transaction->request_body.truncated;\n'
    '         progress->finished = transaction->request_body.finished;\n'
    '         progress->limit_outcome = transaction->request_body.limit_outcome;\n'
    '-        progress->bytes_retained = transaction->request_body.bytes_retained;\n'
    '     }\n'
    ' }\n'
    ' \n'
)
OBSERVER_SOURCE = 'ci/runtime/lifecycle/native-lifecycle-observer.c'
OBSERVER_HASHES = {
    OBSERVER_SOURCE: (
        'ad8e5e36a17e746cf202c685dbb529fc09717f5c25441b713fa369420aa55ac6',
        '0d903fc5e6432769a136931b7ebea16a6f87db941d28d23583ccccf4c75e6537'),
    'ci/runtime/lifecycle/native-lifecycle-observer.h': (
        'f9f63b62ba8efc555dc20e673cc02251d5ab6c2ab17d8f5efa760d0d97146dcd',
        '5b7d8fa7c327017cafb05b1e932f70eefe8641797751a0dc19df0337f4893b1b'),
}
CURRENT_OBSERVER_SUCCESSOR = '5038d0068cef52f7cf4f2013355cf1b828648061993dd89c51d14f5439cfe387'
SUCCESSOR_ADAPTER_CONTRACT = 'i12.envoy.preserve-source-observer.v2'


def accepted_observer_hashes(name, archived):
    accepted = (archived,)
    if name == OBSERVER_SOURCE:
        accepted += (CURRENT_OBSERVER_SUCCESSOR,)
    return accepted


def full_revision(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{40}', value) is None:
        raise ValueError('explicit full lowercase source revision required')
    return value


def registry_adapter_metadata(manifest, revision, manifest_hash, runtime_hash):
    """Permit only the pinned unselected repository object from the e4 archive."""
    if (revision != E4_REVISION or manifest_hash != E4_MANIFEST
            or runtime_hash != E4_CURRENT
            or manifest['objects'].get(E4_STALE) != {'kind': 'repository', 'path': E4_RUNTIME}):
        raise ValueError('unknown stale registry contract')
    profile = manifest['profiles']['envoy']
    if E4_RUNTIME in profile['source_targets']:
        raise ValueError('stale registry object belongs to Envoy profile')
    reachable = {entry['sha256'] for key in ('source_targets', 'capture_files')
                 for entry in profile[key].values()}
    pending = list(reachable)
    while pending:
        identity = pending.pop()
        if identity not in manifest['objects']:
            raise ValueError('unknown Envoy registry dependency')
        item = manifest['objects'][identity]
        if item['kind'] == 'delta' and item['base'] not in reachable:
            reachable.add(item['base'])
            pending.append(item['base'])
    if E4_STALE in reachable:
        raise ValueError('stale registry object belongs to Envoy profile')
    return {'contract': 'i12.envoy.e4-unselected-registry.v1',
            'archived_revision': revision, 'original_manifest_sha256': manifest_hash,
            'repository_path': E4_RUNTIME, 'stale_identity': E4_STALE,
            'preserved_runtime_sha256': runtime_hash,
            'reconstructed_registry_sha256': E4_STALE,
            'verified_object_count': len(manifest['objects']),
            'verified_profile_count': len(manifest['profiles']),
            'envoy_dependency_excluded': True, 'runtime_written': False}


def historical_e4_manifest(data):
    """Recover the exact historical contract from the pinned afaf text anchors."""
    identity = digest(data)
    if identity == E4_MANIFEST:
        return data
    if identity != AFAF_MANIFEST:
        raise ValueError('unknown historical registry manifest bytes')
    manifest = json.loads(data)
    for identity, path in HISTORICAL_REPOSITORY_OBJECTS.items():
        manifest['objects'][identity] = {'kind': 'repository', 'path': path}
    historical = (json.dumps(manifest, indent=2) + '\n').encode()
    if digest(historical) != E4_MANIFEST:
        raise ValueError('reconstructed historical manifest differs')
    return historical


def reverse_exact_patch(patch):
    """Reverse the pinned single-file unified delta without applying it."""
    rows = patch.decode().splitlines(keepends=True)
    if rows[:2] != ['--- a/payload\n', '+++ b/payload\n']:
        raise ValueError('unexpected historical patch header')
    result = rows[:2]
    for row in rows[2:]:
        match = re.fullmatch(
            r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n', row)
        if match is not None:
            old_start, old_count = match[1], match[2] or '1'
            new_start, new_count = match[3], match[4] or '1'
            result.append(f'@@ -{new_start},{new_count} +{old_start},{old_count} @@\n')
        elif row.startswith('-'):
            result.append('+' + row[1:])
        elif row.startswith('+'):
            result.append('-' + row[1:])
        elif row.startswith(' '):
            result.append(row)
        else:
            raise ValueError('unexpected historical patch row')
    return ''.join(result).encode()


def verified_registry(capture, registry, revision, manifest_hash):
    """Verify all registry objects, reconstructing only the pinned e4 contract."""
    if revision != E4_REVISION:
        registry.verify()
        return registry, None
    manifest_data = capture.plain(registry.root / 'manifest.json')
    historical = historical_e4_manifest(manifest_data)
    current_manifest = json.loads(manifest_data)
    historical_manifest = json.loads(historical)
    if (digest(historical) != manifest_hash or registry.manifest not in
            (current_manifest, historical_manifest)):
        raise ValueError('original registry manifest differs')

    if digest(manifest_data) == AFAF_MANIFEST:
        # The current shared registry contains exact lossless anchors for the
        # three repository objects that became unreachable as their source
        # paths advanced. Verify that whole current registry with an empty
        # cache before using those bytes to replay the byte-identical e4
        # registry. The archived build inventory independently proves the e4
        # runtime identified by E4_CURRENT.
        current = copy.copy(registry)
        current.manifest = current_manifest
        current.cache = {}
        current_verification = current.verify()
        if (current_verification['objects'] != len(current_manifest['objects'])
                or current_verification['profiles'] != len(current_manifest['profiles'])):
            raise ValueError('incomplete current registry verification')
        anchors = {identity: current.content(identity)
                   for identity in HISTORICAL_REPOSITORY_OBJECTS}
        reconstructed_runtime = capture.exact_patch(
            anchors[E4_STALE], reverse_exact_patch(E4_INVERSE.encode()))
        runtime_hash = digest(reconstructed_runtime)
    else:
        runtime = capture.plain(registry.repository / E4_RUNTIME)
        runtime_hash = digest(runtime)
        stale = capture.exact_patch(runtime, E4_INVERSE.encode())
        if digest(stale) != E4_STALE:
            raise ValueError('reconstructed registry object differs')
        anchors = {E4_STALE: stale}

    metadata = registry_adapter_metadata(
        historical_manifest, revision, manifest_hash, runtime_hash)
    adapted = copy.copy(registry)
    adapted.manifest = historical_manifest
    # No inherited cache may bypass a physical registry-object check. Only the
    # exact independently verified historical anchors are seeded.
    adapted.cache = anchors
    verification = adapted.verify()
    if (verification['objects'] != metadata['verified_object_count']
            or verification['profiles'] != metadata['verified_profile_count']):
        raise ValueError('incomplete adapted registry verification')
    return adapted, metadata


def observer_contract(profile):
    targets = profile['source_targets']
    for name in targets:
        if Path(name).name in ('native-lifecycle-observer.c', 'native-lifecycle-observer.h') and name not in OBSERVER_HASHES:
            raise ValueError('foreign observer target')
    for name, (historical, _current) in OBSERVER_HASHES.items():
        if targets.get(name) != {'before_sha256': historical, 'sha256': historical, 'mode': 420}:
            raise ValueError('historical observer manifest contract differs: ' + name)


def adapter_metadata(manifest, before, revision, manifest_hash):
    profile = manifest['profiles']['envoy']
    observer_contract(profile)
    if any(before.get(name) not in accepted_observer_hashes(name, current)
           for name, (_old, current) in OBSERVER_HASHES.items()):
        raise ValueError('unknown archived observer hashes')
    contract = (SUCCESSOR_ADAPTER_CONTRACT
                if before.get(OBSERVER_SOURCE) == CURRENT_OBSERVER_SUCCESSOR
                else ADAPTER_CONTRACT)
    return {'contract': contract, 'original_manifest_sha256': manifest_hash,
            'archived_revision': full_revision(revision), 'resolved_revision': revision,
            'applied_targets': {name: entry['sha256'] for name, entry in profile['source_targets'].items()
                                if name not in OBSERVER_HASHES},
            'preserved_targets': {name: {'historical_before_sha256': old, 'archived_sha256': before[name]}
                                  for name, (old, _current) in OBSERVER_HASHES.items()}}


def verify_adapter(proof, expected, manifest):
    """Derive every permitted omission/write from the original archived manifest."""
    revision = full_revision(proof['actual_source_commit'])
    profile = manifest['profiles']['envoy']
    before = {name: expected.get(name) for name in profile['source_targets']}
    metadata = adapter_metadata(manifest, before, revision, expected[MANIFEST])
    if proof['envoy_capture_adapter'] != metadata or proof['source_before_overlay'] != before:
        raise ValueError('Envoy observer adapter metadata differs from archive')
    if proof['manifest_sha256'] != expected[MANIFEST]:
        raise ValueError('original manifest hash differs from archive')
    application = proof['capture_application']
    writes = dict(metadata['applied_targets'])
    writes.update({'.i12-capture/envoy/' + name: entry['sha256']
                   for name, entry in profile['capture_files'].items()})
    if (application['profile'] != 'envoy' or application['source_copy'] != proof['source_copy']
            or application['capture_manifest_sha256'] != expected[MANIFEST]
            or application['actual_before_sha256'] != {name: before[name] for name in metadata['applied_targets']}
            or application['exact_written_sha256'] != writes):
        raise ValueError('Envoy observer adapter application differs from original manifest')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tree_inventory(source):
    result = {}
    for path in sorted(source.rglob('*')):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError('nonphysical source input')
        if path.is_file():
            if path.stat().st_nlink != 1:
                raise ValueError('hard-linked source input')
            result[str(path.relative_to(source))] = digest(path.read_bytes())
    return result


def archive_inventory(data):
    expected = {}
    seen = set()
    manifest = None
    with tarfile.open(fileobj=io.BytesIO(data)) as stream:
        for member in stream:
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError('unsupported source archive entry')
            if member.name in seen:
                raise ValueError('duplicate source archive entry')
            seen.add(member.name)
            if member.isfile():
                body = stream.extractfile(member).read()
                expected[member.name] = digest(body)
                if member.name == 'ci/runtime/lifecycle/i12/manifest.json':
                    manifest = json.loads(body)
    if manifest is None:
        raise ValueError('source archive manifest unavailable')
    return expected, manifest


def verify_revision_and_adapter(proof, expected, manifest):
    if 'source_revision_selection' in proof:
        revision = full_revision(proof['actual_source_commit'])
        if proof['source_revision_selection'] != {'requested': revision, 'resolved': revision}:
            raise ValueError('source revision selection differs')
        resolutions = [check for check in proof['checks'] if check['label'] == 'source-head'
                       and check['exit_code'] == 0
                       and check['argv'] == ['rtk', 'proxy', 'git', 'rev-parse', '--verify', revision + '^{commit}']
                       and check['stdout_sha256'] == digest((revision + '\n').encode())]
        if len(resolutions) != 1:
            raise ValueError('source revision resolution unavailable')
    if 'envoy_capture_adapter' in proof:
        if 'source_revision_selection' not in proof:
            raise ValueError('adapter requires explicit source revision selection')
        verify_adapter(proof, expected, manifest)


def expected_inventory(proof):
    """Reconstruct old receipts too; never bless the current source by hashing it."""
    archive = Path(proof['source_copy']).parent / 'native-build/source-archive.stdout'
    data = archive.read_bytes()
    checks = [check for check in proof['checks'] if check['label'] == 'source-archive'
              and check['exit_code'] == 0
              and check['argv'][-3:] == ['archive', '--format=tar', proof['actual_source_commit']]]
    if len(checks) != 1 or checks[0]['stdout_sha256'] != digest(data):
        raise ValueError('hash-bound original Git archive unavailable')
    expected, manifest = archive_inventory(data)
    if 'envoy_registry_adapter' in proof or proof['actual_source_commit'] == E4_REVISION:
        metadata = registry_adapter_metadata(manifest, proof['actual_source_commit'],
                                             expected[MANIFEST], expected.get(E4_RUNTIME))
        if proof.get('envoy_registry_adapter') != metadata:
            raise ValueError('Envoy registry adapter metadata differs from archive')
    if ('envoy' in manifest.get('profiles', {})
            and any(expected.get(name) != old for name, (old, _current) in OBSERVER_HASHES.items())
            and 'envoy_capture_adapter' not in proof):
        raise ValueError('changed archived observer requires explicit adapter metadata')
    verify_revision_and_adapter(proof, expected, manifest)
    expected.update(proof['capture_application']['exact_written_sha256'])
    prefix = '.i12-capture/envoy/source-copy-tests/'
    copies = {path.removeprefix(prefix): value for path, value in expected.items()
              if path.startswith(prefix)}
    for relative, value in copies.items():
        if relative in expected:
            raise ValueError('capture test overwrites original source')
        expected[relative] = value
    marker = {'format': 'i12-disposable-source-copy-v1', 'path': proof['source_copy'],
              'disposable': True, 'parent_sha': manifest['delivery_product_baseline']}
    expected['.i12-disposable-source-copy.json'] = digest(json.dumps(marker).encode())
    expected['i12-source-application-receipt.json'] = digest(
        (json.dumps(proof['capture_application'], indent=2) + '\n').encode())
    return expected


def verify(source, proof):
    expected = expected_inventory(proof)
    actual = tree_inventory(source)
    changed = sorted(name for name in set(expected) | set(actual) if expected.get(name) != actual.get(name))
    if changed:
        raise ValueError('complete build-source inventory mismatch: ' + ', '.join(changed[:8]))
    return expected
