"""Current-base observer adapter controls against the original capture registry."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest

if __package__:
    from . import prepare_native as prepare
    from . import source_inventory as inventory
else:
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.prepare_native as prepare
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.source_inventory as inventory


class ObserverHashControls(unittest.TestCase):
    def test_observer_source_accepts_archived_hash(self):
        archived = inventory.OBSERVER_HASHES[inventory.OBSERVER_SOURCE][1]
        accepted = inventory.accepted_observer_hashes(inventory.OBSERVER_SOURCE, archived)
        self.assertIn(archived, accepted)
        self.assertEqual(accepted, (archived, inventory.CURRENT_OBSERVER_SUCCESSOR))

    def test_observer_source_accepts_pinned_successor_hash(self):
        archived = inventory.OBSERVER_HASHES[inventory.OBSERVER_SOURCE][1]
        accepted = inventory.accepted_observer_hashes(inventory.OBSERVER_SOURCE, archived)
        self.assertIn(inventory.CURRENT_OBSERVER_SUCCESSOR, accepted)
        self.assertNotIn("unreviewed-observer", accepted)

    def test_observer_header_accepts_only_archived_hash(self):
        name = 'ci/runtime/lifecycle/native-lifecycle-observer.h'
        archived = inventory.OBSERVER_HASHES[name][1]
        accepted = inventory.accepted_observer_hashes(name, archived)
        self.assertEqual(accepted, (archived,))
        self.assertNotIn(inventory.CURRENT_OBSERVER_SUCCESSOR, accepted)
        self.assertNotIn("unreviewed-observer", accepted)


class ObserverAdapterControls(unittest.TestCase):
    def setUp(self):
        self.repository = connector_root()
        self.capture = prepare.load(source_path('ci/runtime/lifecycle/i12/capture_sources.py', root=self.repository),
                                    'adapter_capture_controls')
        self.registry = self.capture.Registry(
            root=source_path('ci/runtime/lifecycle/i12', root=self.repository), repository=self.repository)
        self.temporary = tempfile.TemporaryDirectory(
            dir=self.registry.manifest['authorized_storage_root'])
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.profile = self.registry.manifest['profiles']['envoy']
        self.original = {inventory.MANIFEST: (self.registry.root / 'manifest.json').read_bytes()}
        for name in self.profile['source_targets']:
            self.original[name] = source_path(name, root=self.repository).read_bytes()
        for name, data in self.original.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        marker = {'format': 'i12-disposable-source-copy-v1', 'path': str(self.source),
                  'disposable': True, 'parent_sha': self.registry.manifest['delivery_product_baseline']}
        (self.source / self.capture.MARKER).write_text(json.dumps(marker))
        self.proof = {'source_copy': str(self.source), 'actual_source_commit': 'a' * 40,
                      'manifest_sha256': prepare.sha(self.source / inventory.MANIFEST),
                      'source_before_overlay': {name: prepare.sha(self.source / name)
                                                for name in self.profile['source_targets']}}

    def tearDown(self):
        self.temporary.cleanup()

    def apply(self):
        self.proof['capture_application'] = prepare.apply_capture(
            self.capture, self.registry, self.source, self.proof)

    def bind_archive(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as stream:
            for name, body in self.original.items():
                member = tarfile.TarInfo(name)
                member.size = len(body)
                stream.addfile(member, io.BytesIO(body))
        out = self.root / 'native-build'
        out.mkdir()
        (out / 'source-archive.stdout').write_bytes(output.getvalue())
        revision = self.proof['actual_source_commit']
        self.proof['source_revision_selection'] = {'requested': revision, 'resolved': revision}
        self.proof['checks'] = [
            {'label': 'source-archive', 'exit_code': 0,
             'argv': ['rtk', 'proxy', 'git', 'archive', '--format=tar', revision],
             'stdout_sha256': inventory.digest(output.getvalue())},
            {'label': 'source-head', 'exit_code': 0,
             'argv': ['rtk', 'proxy', 'git', 'rev-parse', '--verify', revision + '^{commit}'],
             'stdout_sha256': inventory.digest((revision + '\n').encode())}]
        for name in self.profile['capture_files']:
            if name.startswith('source-copy-tests/'):
                relative = name.removeprefix('source-copy-tests/')
                (self.source / relative).write_bytes((self.source / '.i12-capture/envoy' / name).read_bytes())

    def test_preserves_exact_current_observers_and_full_inventory(self):
        original_manifest = copy.deepcopy(self.registry.manifest)
        self.apply()
        self.assertEqual(self.registry.manifest, original_manifest)
        metadata = self.proof['envoy_capture_adapter']
        self.assertEqual(metadata['contract'], inventory.ADAPTER_CONTRACT)
        self.assertEqual(len(metadata['applied_targets']), 9)
        self.assertEqual(set(metadata['preserved_targets']), set(inventory.OBSERVER_HASHES))
        for name, (_old, current) in inventory.OBSERVER_HASHES.items():
            self.assertEqual(prepare.sha(self.source / name), current)
            self.assertNotIn(name, self.proof['capture_application']['exact_written_sha256'])
        self.bind_archive()
        inventory.verify(self.source, self.proof)
        for name in inventory.OBSERVER_HASHES:
            with self.subTest(name=name):
                (self.source / name).write_bytes(b'changed observer')
                with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
                    inventory.verify(self.source, self.proof)
                (self.source / name).write_bytes(self.original[name])

    def test_historical_observers_use_original_application_without_adapter(self):
        for name, (old, _current) in inventory.OBSERVER_HASHES.items():
            self.original[name] = self.registry.content(old)
            (self.source / name).write_bytes(self.original[name])
            self.proof['source_before_overlay'][name] = old
        self.apply()
        self.assertNotIn('envoy_capture_adapter', self.proof)
        self.assertEqual(len(self.proof['capture_application']['actual_before_sha256']), 11)
        self.bind_archive()
        self.proof.pop('source_revision_selection')
        self.proof['checks'][1]['argv'] = ['rtk', 'proxy', 'git', 'rev-parse', 'HEAD']
        expected = inventory.verify(self.source, self.proof)
        for name, (old, _current) in inventory.OBSERVER_HASHES.items():
            self.assertEqual(expected[name], old)
            self.assertEqual(prepare.sha(self.source / name), old)
            self.assertEqual(self.proof['capture_application']['exact_written_sha256'][name], old)
        # A legacy receipt remains subject to the complete physical inventory.
        name = next(iter(inventory.OBSERVER_HASHES))
        (self.source / name).write_bytes(b'changed historical observer')
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            inventory.verify(self.source, self.proof)

    def test_unknown_or_mixed_observer_hashes_fail_before_overlay(self):
        for replacement in (b'unknown observer', self.registry.content(
                next(iter(inventory.OBSERVER_HASHES.values()))[0])):
            with self.subTest(replacement=inventory.digest(replacement)):
                name = next(iter(inventory.OBSERVER_HASHES))
                (self.source / name).write_bytes(replacement)
                self.proof['source_before_overlay'][name] = inventory.digest(replacement)
                with self.assertRaisesRegex(ValueError, 'unknown archived observer'):
                    self.apply()
                self.assertFalse((self.source / '.i12-capture').exists())

    def test_foreign_observer_and_changed_historical_manifest_fail_closed(self):
        targets = self.profile['source_targets']
        name = next(iter(inventory.OBSERVER_HASHES))
        targets['foreign/native-lifecycle-observer.c'] = targets[name]
        with self.assertRaisesRegex(ValueError, 'foreign observer'):
            self.apply()
        del targets['foreign/native-lifecycle-observer.c']
        targets[name] = {**targets[name], 'before_sha256': '0' * 64}
        with self.assertRaisesRegex(ValueError, 'historical observer manifest'):
            self.apply()
        self.assertFalse((self.source / '.i12-capture').exists())

    def test_corrupt_unselected_registry_object_is_not_skipped(self):
        # Poison an object outside Envoy, retaining its original identity.
        identity = next(key for key in self.registry.manifest['objects']
                        if key not in {entry['sha256'] for entry in self.profile['source_targets'].values()})
        self.registry.manifest['objects'][identity] = {'kind': 'unknown-corrupt-kind'}
        with self.assertRaisesRegex(ValueError, 'Unknown source object kind'):
            self.apply()
        self.assertFalse((self.source / '.i12-capture').exists())

    def test_metadata_omissions_substitutions_and_extra_writes_are_rejected(self):
        self.apply()
        self.bind_archive()
        baseline = copy.deepcopy(self.proof)
        mutations = [
            lambda proof: proof.pop('envoy_capture_adapter'),
            lambda proof: proof.pop('source_revision_selection'),
            lambda proof: proof['envoy_capture_adapter'].update(contract='different'),
            lambda proof: proof['envoy_capture_adapter']['preserved_targets'].pop(next(iter(inventory.OBSERVER_HASHES))),
            lambda proof: proof['envoy_capture_adapter']['preserved_targets'].update({'foreign/observer.c': {}}),
            lambda proof: proof['envoy_capture_adapter'].update(original_manifest_sha256='0' * 64),
            lambda proof: proof['envoy_capture_adapter'].update(archived_revision='b' * 40),
            lambda proof: proof['envoy_capture_adapter']['applied_targets'].pop(next(iter(
                proof['envoy_capture_adapter']['applied_targets']))),
            lambda proof: proof['capture_application']['exact_written_sha256'].update({'extra.c': '0' * 64}),
            lambda proof: proof['source_before_overlay'].update({next(iter(inventory.OBSERVER_HASHES)): '0' * 64}),
            lambda proof: proof['source_revision_selection'].update(requested='HEAD'),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                proof = copy.deepcopy(baseline)
                mutate(proof)
                with self.assertRaises(ValueError):
                    inventory.verify(self.source, proof)

    def test_applied_and_preserved_hash_substitutions_are_rejected(self):
        self.apply()
        self.bind_archive()
        baseline = copy.deepcopy(self.proof)
        applied = next(iter(baseline['envoy_capture_adapter']['applied_targets']))
        for name, field in ((applied, 'applied_targets'), *(
                (name, field) for name in inventory.OBSERVER_HASHES
                for field in ('archived_sha256', 'historical_before_sha256'))):
            with self.subTest(target=name, field=field):
                proof = copy.deepcopy(baseline)
                metadata = proof['envoy_capture_adapter']
                if field == 'applied_targets':
                    metadata[field][name] = '0' * 64
                else:
                    metadata['preserved_targets'][name][field] = '0' * 64
                with self.assertRaisesRegex(ValueError, 'adapter metadata differs from archive'):
                    inventory.verify(self.source, proof)

    def test_application_profile_manifest_and_before_hash_substitutions_are_rejected(self):
        self.apply()
        self.bind_archive()
        baseline = copy.deepcopy(self.proof)
        target = next(iter(baseline['capture_application']['actual_before_sha256']))
        mutations = {
            'profile': lambda application: application.update(profile='foreign'),
            'capture_manifest_sha256': lambda application: application.update(capture_manifest_sha256='0' * 64),
            'actual_before_sha256': lambda application: application['actual_before_sha256'].update({target: '0' * 64}),
        }
        for field, mutate in mutations.items():
            with self.subTest(field=field):
                proof = copy.deepcopy(baseline)
                mutate(proof['capture_application'])
                with self.assertRaisesRegex(ValueError, 'adapter application differs from original manifest'):
                    inventory.verify(self.source, proof)

    def test_full_sha_is_required_and_resolution_must_be_identical(self):
        for revision in ('HEAD', 'a62296f', 'A' * 40, 'a' * 40 + '^', None):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                prepare.prepare_source(self.source, {}, lambda *_args: b'', revision)
        calls = []
        def changed_resolution(label, argv):
            calls.append((label, argv))
            return ('b' * 40 + '\n').encode()
        with self.assertRaisesRegex(ValueError, 'resolved source revision differs'):
            prepare.prepare_source(self.source, {}, changed_resolution, 'a' * 40)
        self.assertEqual(calls, [('source-head', ['git', 'rev-parse', '--verify', 'a' * 40 + '^{commit}'])])


class E4RegistryAdapterControls(unittest.TestCase):
    setUp = ObserverAdapterControls.setUp
    tearDown = ObserverAdapterControls.tearDown
    bind_archive = ObserverAdapterControls.bind_archive
    apply = ObserverAdapterControls.apply

    def activate(self):
        self.registry.cache.clear()
        self.proof['actual_source_commit'] = inventory.E4_REVISION
        current = self.capture.Registry(
            root=source_path('ci/runtime/lifecycle/i12', root=self.repository), repository=self.repository)
        stale = current.content(inventory.E4_STALE)
        runtime = self.capture.exact_patch(
            stale, inventory.reverse_exact_patch(inventory.E4_INVERSE.encode()))
        self.assertEqual(inventory.digest(runtime), inventory.E4_CURRENT)
        historical = inventory.historical_e4_manifest(self.original[inventory.MANIFEST])
        self.registry.manifest = json.loads(historical)
        self.profile = self.registry.manifest['profiles']['envoy']
        self.original[inventory.MANIFEST] = historical
        (self.source / inventory.MANIFEST).write_bytes(historical)
        self.proof['manifest_sha256'] = inventory.E4_MANIFEST
        self.original[inventory.E4_RUNTIME] = runtime
        path = self.source / inventory.E4_RUNTIME
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.original[inventory.E4_RUNTIME])

    def test_exact_e4_registry_verifies_all_objects_preserving_runtime_and_manifest(self):
        self.activate()
        original_manifest = copy.deepcopy(self.registry.manifest)
        self.apply()
        metadata = self.proof['envoy_registry_adapter']
        self.assertEqual(metadata['verified_object_count'], 155)
        self.assertEqual(metadata['verified_profile_count'], 10)
        self.assertEqual(self.registry.manifest, original_manifest)
        self.assertEqual(self.registry.cache, {})
        self.assertNotIn(inventory.E4_RUNTIME,
                         self.proof['capture_application']['exact_written_sha256'])
        # apply_capture runs from today's afaf registry root in this unit
        # fixture. The reconstructed source and manifest are exact e4 bytes,
        # so model the application receipt that the real e4 archive wrote.
        self.proof['capture_application']['capture_manifest_sha256'] = inventory.E4_MANIFEST
        (self.source / 'i12-source-application-receipt.json').write_text(
            json.dumps(self.proof['capture_application'], indent=2) + '\n')
        self.bind_archive()
        expected = inventory.verify(self.source, self.proof)
        self.assertEqual(expected[inventory.E4_RUNTIME], inventory.E4_CURRENT)
        self.assertEqual(prepare.sha(self.source / inventory.E4_RUNTIME), inventory.E4_CURRENT)
        self.assertEqual(prepare.sha(self.source / inventory.MANIFEST), inventory.E4_MANIFEST)
        baseline = copy.deepcopy(self.proof)
        for field in metadata:
            with self.subTest(field=field):
                proof = copy.deepcopy(baseline)
                proof['envoy_registry_adapter'][field] = 'substituted'
                with self.assertRaises(ValueError):
                    inventory.verify(self.source, proof)
        proof = copy.deepcopy(baseline)
        proof.pop('envoy_registry_adapter')
        with self.assertRaises(ValueError):
            inventory.verify(self.source, proof)
        (self.source / inventory.E4_RUNTIME).write_bytes(b'extra runtime drift')
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            inventory.verify(self.source, baseline)

    def test_afaf_registry_is_verified_directly_before_historical_replay(self):
        original_manifest = copy.deepcopy(self.registry.manifest)
        original_cache = copy.deepcopy(self.registry.cache)
        current, metadata = inventory.verified_registry(
            self.capture, self.registry, 'a' * 40,
            inventory.digest(self.original[inventory.MANIFEST]))
        self.assertIs(current, self.registry)
        self.assertIsNone(metadata)
        self.assertEqual(self.registry.manifest, original_manifest)
        self.assertEqual(original_cache, {})
        self.assertEqual(len(self.registry.cache), 155)

        self.activate()
        original_manifest = copy.deepcopy(self.registry.manifest)
        adapted, metadata = inventory.verified_registry(
            self.capture, self.registry, inventory.E4_REVISION, inventory.E4_MANIFEST)
        self.assertEqual(self.registry.manifest, original_manifest)
        self.assertEqual(self.registry.cache, {})
        self.assertEqual(metadata['preserved_runtime_sha256'], inventory.E4_CURRENT)
        self.assertEqual(len(adapted.cache), 155)
        for identity in inventory.HISTORICAL_REPOSITORY_OBJECTS:
            self.assertEqual(inventory.digest(adapted.content(identity)), identity)

    def test_revision_manifest_path_profile_and_runtime_mutations_fail_closed(self):
        self.activate()
        manifest = self.registry.manifest
        arguments = [manifest, inventory.E4_REVISION, inventory.E4_MANIFEST, inventory.E4_CURRENT]
        for index in (1, 2, 3):
            with self.subTest(argument=index):
                mutated = list(arguments)
                mutated[index] = '0' * len(arguments[index])
                with self.assertRaises(ValueError):
                    inventory.registry_adapter_metadata(*mutated)
        for mutate in (
                lambda m: m['objects'][inventory.E4_STALE].update(path='foreign/runtime.c'),
                lambda m: m['objects'][inventory.E4_STALE].update(kind='text'),
                lambda m: m['profiles']['envoy']['capture_files'].update(
                    {'foreign.c': {'sha256': inventory.E4_STALE}}),
                lambda m: m['profiles']['envoy']['capture_files'].update(
                    {'foreign-delta.c': {'sha256': next(
                        key for key, item in m['objects'].items()
                        if item.get('base') == inventory.E4_STALE)}}),
                lambda m: m['profiles']['envoy']['source_targets'].update(
                    {inventory.E4_RUNTIME: {'sha256': inventory.E4_CURRENT}})):
            mutated = copy.deepcopy(manifest)
            mutate(mutated)
            with self.assertRaises(ValueError):
                inventory.registry_adapter_metadata(mutated, *arguments[1:])
        self.proof['manifest_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            self.apply()
        self.assertFalse((self.source / '.i12-capture').exists())

    def test_other_registry_drift_is_verified_despite_seeded_stale_object(self):
        self.activate()
        # The manifest remains byte-identical. Force an unselected physical
        # object's bytes to drift instead of changing its declared identity.
        original_content = self.registry.content
        identity = next(key for key, value in self.registry.manifest['objects'].items()
                        if value['kind'] == 'text')
        def drift(key, trail=()):
            if key == identity:
                raise ValueError('independent registry object drift')
            return original_content(key, trail)
        self.registry.content = drift
        with self.assertRaisesRegex(ValueError, 'independent registry object drift'):
            self.apply()
        self.assertFalse((self.source / '.i12-capture').exists())


class GoProvenanceControls(unittest.TestCase):
    def setUp(self):
        import os
        from unittest.mock import patch
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
        selected = os.environ.get('I12_TEST_ROOT') or os.environ['RUNNER_TEMP']
        storage = validate_output_root(prepare.evidence_io.REPOSITORY, Path(selected))
        self.temporary = tempfile.TemporaryDirectory(prefix='envoy-go-provenance-', dir=storage)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        roots = patch.object(prepare.evidence_io, 'DEFAULT_ROOTS', (self.root,))
        roots.start()
        self.addCleanup(roots.stop)
        (self.root / 'bin').mkdir()
        self.go = self.root / 'bin/go'
        self.go.write_bytes(b'physical test executable identity')
        self.go.chmod(0o755)
        self.env = {'PATH': str(self.root / 'bin'), 'GOTOOLCHAIN': 'local',
                    'GOROOT': str(self.root), 'GOOS': 'linux', 'GOARCH': 'amd64'}
        self.profile = {'provenance': {'go_version': '1.27.2'}}
        self.receipt = {}
        self.calls = []
        self.output = b'go version go1.27.2 linux/amd64\n'
        self.environment_output = (str(self.root) + '\nlinux\namd64\ngo1.27.2\n' +
                                   str(self.root / 'pkg/tool/linux_amd64') + '\n').encode()
        self.tool_outputs = {}
        for name in ('compile', 'link'):
            path = self.root / 'pkg/tool/linux_amd64' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('physical ' + name + ' test tool').encode())
            self.tool_outputs[name] = (name + ' version go1.27.2\n').encode()

        class Runner:
            def __call__(_runner, label, argv, *_args):
                self.calls.append((label, argv))
                if label == 'go-environment':
                    return self.environment_output
                if label in ('go-compile-version', 'go-link-version'):
                    return self.tool_outputs[label.removeprefix('go-').removesuffix('-version')]
                return self.output

            def save(_runner):
                pass  # This command recorder retains calls in memory; it intentionally writes no receipt.

        self.run = Runner()

    def tearDown(self):
        self.temporary.cleanup()

    def capture(self):
        prepare.record_go_provenance(self.go, self.env, self.receipt, self.run, self.profile)

    def test_exact_identity_records_required_actual_and_physical_executable(self):
        self.capture()
        self.assertEqual(self.calls, [
            ('go-version', [self.go, 'version']),
            ('go-environment', [self.go, 'env', 'GOROOT', 'GOOS', 'GOARCH', 'GOVERSION', 'GOTOOLDIR']),
            ('go-compile-version', [self.root / 'pkg/tool/linux_amd64/compile', '-V']),
            ('go-link-version', [self.root / 'pkg/tool/linux_amd64/link', '-V'])])
        identity = self.receipt['go_provenance']
        self.assertEqual({key: identity[key] for key in (
            'required_version', 'required_identity', 'actual_identity', 'configured_path',
            'executable_path', 'executable_sha256', 'verified')}, {
            'required_version': '1.27.2', 'required_identity': 'go version go1.27.2 linux/amd64',
            'actual_identity': 'go version go1.27.2 linux/amd64',
            'configured_path': str(self.go), 'executable_path': str(self.go),
            'executable_sha256': prepare.sha(self.go), 'verified': True})
        self.assertEqual(identity['actual_environment'], identity['required_environment'])
        for name in ('compile', 'link'):
            item = identity['tools'][name]
            self.assertEqual(item['path'], str(self.root / 'pkg/tool/linux_amd64' / name))
            self.assertEqual(item['sha256'], prepare.sha(Path(item['path'])))
            self.assertEqual(item['actual_identity'], name + ' version go1.27.2')

    def test_wrong_patch_release_is_recorded_and_rejected_before_any_build(self):
        self.output = b'go version go1.27.3 linux/amd64\n'
        sdk = self.root / 'libmodsecurity.so'
        sdk.write_bytes(b'test sdk identity')
        self.profile['provenance']['sdk_image_sha256'] = prepare.sha(sdk)
        args = SimpleNamespace(go=self.go, sdk_library=sdk)
        with self.assertRaisesRegex(ValueError, 'exact capture provenance'):
            prepare.compile_native(args, self.root / 'absent-source', self.root,
                                   self.env, self.receipt, self.run, self.profile)
        self.assertEqual(self.calls, [('go-version', [self.go, 'version'])])
        self.assertFalse(self.receipt['go_provenance']['verified'])
        self.assertEqual(self.receipt['go_provenance']['actual_identity'], 'go version go1.27.3 linux/amd64')
        self.assertNotIn('build_ready', self.receipt)

    def test_format_platform_development_and_extra_output_mutations_are_rejected(self):
        for output in (b'go version go1.27.2 linux/arm64\n', b'go version go1.27.2 darwin/amd64\n',
                       b'go version devel go1.27.2 linux/amd64\n', b'go version go1.27.2rc1 linux/amd64\n',
                       b'go version go1.27.2 linux/amd64', b'go version go1.27.2 linux/amd64\r\n',
                       b'go version go1.27.2 linux/amd64\nextra\n', b'go version go1.27.2 linux/amd64 \n',
                       b'go version go1.27.2 linux/amd64\xff\n', b''):
            with self.subTest(output=output):
                self.output = output
                with self.assertRaisesRegex(ValueError, 'exact capture provenance'):
                    self.capture()
                self.assertFalse(self.receipt['go_provenance']['verified'])

    def test_inexact_manifest_version_is_rejected_before_invocation(self):
        for version in ('go1.27.2', '1.27', '1.27.2rc1', '1.27.2\n', None):
            with self.subTest(version=version):
                self.profile['provenance']['go_version'] = version
                with self.assertRaisesRegex(ValueError, 'exact capture Go version required'):
                    self.capture()
        self.assertEqual(self.calls, [])

    def test_cross_platform_auto_toolchain_and_other_path_selection_are_rejected(self):
        for changes in ({'GOOS': 'windows'}, {'GOARCH': 'arm64'}, {'GOTOOLCHAIN': 'auto'},
                        {'PATH': ''}, {'GOROOT': '/usr/local/go'}):
            with self.subTest(changes=changes):
                self.env = {'PATH': str(self.root / 'bin'), 'GOTOOLCHAIN': 'local',
                            'GOROOT': str(self.root), 'GOOS': 'linux', 'GOARCH': 'amd64', **changes}
                with self.assertRaisesRegex(ValueError, 'selected local Go executable'):
                    self.capture()
        self.assertEqual(self.calls, [])

    def test_changed_executable_during_version_capture_is_rejected(self):
        def changing_run(label, argv):
            self.go.write_bytes(b'substituted Go executable')
            return self.output
        changing_run.save = lambda: None
        self.run = changing_run
        with self.assertRaisesRegex(ValueError, 'changed during provenance capture'):
            self.capture()
        self.assertFalse(self.receipt['go_provenance']['verified'])

    def test_configuration_overwrites_inherited_foreign_toolchain_environment(self):
        cache = self.root / 'module-cache'
        cache.mkdir()
        run_root = self.root / 'run'
        run_root.mkdir()
        sdk = self.root / 'sdk.so'
        sdk.write_bytes(b'test sdk')
        args = SimpleNamespace(go=self.go, module_cache=cache, tmp_root=None,
                               sdk_include=self.root, sdk_library=sdk)
        self.env.update(GOROOT='/usr/local/go', GOOS='windows', GOARCH='arm64', GOTOOLCHAIN='auto')
        prepare.configure_native_environment(args, run_root, run_root / 'native-build', self.receipt, self.env)
        for key, expected in {'GOROOT': str(self.root), 'GOOS': 'linux', 'GOARCH': 'amd64',
                              'GOTOOLCHAIN': 'local'}.items():
            self.assertEqual(self.env[key], expected)
            self.assertEqual(self.receipt['environment'][key], expected)
        self.capture()
        self.assertTrue(self.receipt['go_provenance']['verified'])

    def test_go_environment_identity_and_format_substitutions_are_rejected(self):
        original = self.environment_output
        for replacement in (original.replace(str(self.root).encode(), b'/usr/local/go'),
                            original.replace(b'linux\n', b'windows\n'),
                            original.replace(b'amd64\n', b'arm64\n'),
                            original.replace(b'go1.27.2\n', b'go1.27.3\n'),
                            original.replace(b'pkg/tool/linux_amd64', b'foreign-tool-directory'),
                            original.rstrip(b'\n'), original + b'extra\n', original.replace(b'\n', b'\r\n')):
            with self.subTest(output=replacement):
                self.environment_output = replacement
                with self.assertRaisesRegex(ValueError, 'environment differs from isolated capture toolchain'):
                    self.capture()
                self.assertFalse(self.receipt['go_provenance']['verified'])

    def test_wrong_compile_or_link_tool_version_is_rejected(self):
        for name in ('compile', 'link'):
            with self.subTest(tool=name):
                self.tool_outputs = {tool: (tool + ' version go1.27.2\n').encode()
                                     for tool in ('compile', 'link')}
                self.tool_outputs[name] = (name + ' version go1.27.3\n').encode()
                with self.assertRaisesRegex(ValueError, 'tool version differs.*' + name):
                    self.capture()
                self.assertFalse(self.receipt['go_provenance']['verified'])

    def test_driver_compile_and_link_are_rehashed_after_build(self):
        self.capture()
        baseline = self.receipt['go_provenance']
        for path in (self.go, *(self.root / 'pkg/tool/linux_amd64' / name for name in ('compile', 'link'))):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.write_bytes(b'substituted after build')
                with self.assertRaisesRegex(ValueError, 'toolchain executable changed'):
                    prepare.verify_go_toolchain_hashes(baseline)
                path.write_bytes(original)

    def test_foreign_tool_symlink_is_rejected_before_tool_invocation(self):
        path = self.root / 'pkg/tool/linux_amd64/compile'
        path.unlink()
        path.symlink_to(self.go)
        with self.assertRaisesRegex(ValueError, 'tool must be physical inside selected GOROOT'):
            self.capture()
        self.assertEqual([label for label, _argv in self.calls], ['go-version', 'go-environment'])




class HashBoundaryControls(unittest.TestCase):
    """Inert source/installed-image hashing; never invoke a SDK or Go tool."""
    def setUp(self):
        import os
        from unittest.mock import patch
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
        storage = validate_output_root(prepare.evidence_io.REPOSITORY, Path(os.environ['RUNNER_TEMP']))
        temporary = tempfile.TemporaryDirectory(prefix='envoy-hash-boundary-', dir=storage)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.evidence = self.root / 'evidence'
        self.installed = self.root / 'public-install'
        self.evidence.mkdir(mode=0o700)
        self.installed.mkdir(mode=0o700)
        self.production_install_roots = prepare.PUBLIC_INSTALL_ROOTS
        # Only this trusted unit fixture supplies an alternate policy. No CLI,
        # receipt metadata or candidate parent directory becomes an allowlist.
        roots = patch.object(prepare.evidence_io, 'DEFAULT_ROOTS', (self.evidence,))
        public = patch.object(prepare, 'PUBLIC_INSTALL_ROOTS', (self.installed,))
        roots.start()
        self.addCleanup(roots.stop)
        public.start()
        self.addCleanup(public.stop)

    def _file(self, relative, data=b'inert hash-bound input', *, public=False):
        path = (self.installed if public else self.evidence) / relative
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def _expected(self, data):
        import hashlib
        return hashlib.sha256(data).hexdigest()

    def test_public_install_roots_are_fixed_independent_policy(self):
        self.assertEqual(self.production_install_roots, tuple(map(Path, (
            '/usr/include', '/usr/lib', '/usr/local/lib', '/usr/bin', '/usr/local/go'))))

    def test_physical_evidence_hashes_real_bytes(self):
        data = b'independent evidence digest input'
        self.assertEqual(prepare.sha(self._file('input.json', data)), self._expected(data))

    def test_outside_path_rejects_before_resolve_or_open(self):
        from unittest.mock import patch
        path = self.root / 'outside' / 'unread'
        with patch.object(Path, 'resolve', side_effect=AssertionError('unchecked resolve')) as resolve, \
                patch.object(prepare.evidence_io, 'open_evidence') as opened:
            with self.assertRaisesRegex(ValueError, 'outside approved'):
                prepare.sha(path)
        resolve.assert_not_called()
        opened.assert_not_called()

    def test_private_configuration_rejects_before_resolve_or_open(self):
        from unittest.mock import patch
        path = self.evidence / '.aws' / 'credentials'
        with patch.object(Path, 'resolve', side_effect=AssertionError('unchecked resolve')) as resolve, \
                patch.object(prepare.evidence_io, 'open_evidence') as opened:
            with self.assertRaisesRegex(ValueError, 'private configuration'):
                prepare.sha(path)
        resolve.assert_not_called()
        opened.assert_not_called()

    def test_traversal_rejects_before_resolve_or_open(self):
        from unittest.mock import patch
        path = self.evidence / '..' / 'evidence' / 'input'
        with patch.object(Path, 'resolve', side_effect=AssertionError('unchecked resolve')) as resolve, \
                patch.object(prepare.evidence_io, 'open_evidence') as opened:
            with self.assertRaisesRegex(ValueError, 'without traversal'):
                prepare.sha(path)
        resolve.assert_not_called()
        opened.assert_not_called()

    def test_evidence_final_symlink_is_rejected_without_resolving(self):
        from unittest.mock import patch
        target = self._file('physical')
        alias = self.evidence / 'alias'
        alias.symlink_to(target)
        with patch.object(Path, 'resolve', side_effect=AssertionError('evidence link resolved')):
            with self.assertRaises((OSError, ValueError)):
                prepare.sha(alias)

    def test_evidence_ancestor_symlink_is_rejected_without_resolving(self):
        from unittest.mock import patch
        self._file('physical/input')
        alias = self.evidence / 'alias'
        alias.symlink_to(self.evidence / 'physical', target_is_directory=True)
        with patch.object(Path, 'resolve', side_effect=AssertionError('evidence link resolved')):
            with self.assertRaises((OSError, ValueError)):
                prepare.sha(alias / 'input')

    def test_installed_sdk_library_symlink_hashes_approved_target(self):
        data = b'inert public SDK image; never loaded'
        target = self._file('lib/libmodsecurity.so.3', data, public=True)
        alias = self.installed / 'lib/libmodsecurity.so'
        alias.symlink_to(target.name)
        self.assertEqual(prepare.sha(alias), self._expected(data))

    def test_installed_sdk_header_hashes_approved_bytes(self):
        data = b'/* inert SDK header input */'
        path = self._file('include/modsecurity/transaction.h', data, public=True)
        self.assertEqual(prepare.sha(path), self._expected(data))

    def test_installed_symlink_escape_rejects_before_descriptor_open(self):
        from unittest.mock import patch
        target = self.root / 'outside-image'
        target.write_bytes(b'outside approved image roots')
        alias = self.installed / 'escape.so'
        alias.symlink_to(target)
        with patch.object(prepare.evidence_io, 'open_evidence') as opened:
            with self.assertRaisesRegex(ValueError, 'outside approved'):
                prepare.sha(alias)
        opened.assert_not_called()

    def test_installed_symlink_cannot_escape_into_approved_evidence(self):
        from unittest.mock import patch
        target = self._file('evidence-is-not-an-installed-image')
        alias = self.installed / 'escape-into-evidence.so'
        alias.symlink_to(target)
        with patch.object(prepare.evidence_io, 'open_evidence') as opened:
            with self.assertRaisesRegex(ValueError, 'outside approved'):
                prepare.sha(alias)
        opened.assert_not_called()

    def test_configured_external_go_driver_hashes_physical_bytes(self):
        data = b'inert configured Go driver; never executed'
        path = self._file('go/bin/go', data)
        self.assertEqual(prepare.sha(path), self._expected(data))

    def test_configured_external_go_compile_tool_hashes_physical_bytes(self):
        data = b'inert configured Go compile tool; never executed'
        path = self._file('go/pkg/tool/linux_amd64/compile', data)
        self.assertEqual(prepare.sha(path), self._expected(data))

    def test_configured_external_go_link_tool_hashes_physical_bytes(self):
        data = b'inert configured Go link tool; never executed'
        path = self._file('go/pkg/tool/linux_amd64/link', data)
        self.assertEqual(prepare.sha(path), self._expected(data))

    def test_installed_go_driver_symlink_hashes_approved_target(self):
        data = b'inert public Go driver; never executed'
        target = self._file('go/bin/go', data, public=True)
        alias = self.installed / 'bin/go'
        alias.parent.mkdir(mode=0o700)
        alias.symlink_to(target)
        self.assertEqual(prepare.sha(alias), self._expected(data))


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
