"""Contracts for the separately built native NGINX response-buffer fixture.

These checks protect fixture wiring only. The native runner is the behavioral
proof because it builds a dedicated test binary and traverses the real NGINX
filter chain.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import ast
from contextlib import ExitStack, contextmanager
import hashlib
import io
import os
import tarfile
from types import SimpleNamespace
from unittest import mock
import importlib.util
import unittest
import tempfile
from pathlib import Path


ROOT = connector_root()
FIXTURE = source_path('tests/nginx_body_buffer_fixture', root=ROOT)
MODULE = FIXTURE / "ngx_http_body_buffer_fixture_module.c"
RUNNER = source_path('tests/run_nginx_body_buffer_fixture.py', root=ROOT)


def load_runner():
    module = load_source(RUNNER)
    return module


RUNNER_MODULE = load_runner()
P3_RUNNER_MODULE = load_source(source_path("tests/run_nginx_p3_header_fixture.py", root=ROOT))


class NginxBodyBufferFixtureContractTest(unittest.TestCase):
    @staticmethod
    def _positive_events() -> list[dict[str, object]]:
        return [
            {
                "uri": "/" + mode,
                "event": "phase4_intervention",
                "phase": "response_body",
                "rule_id": "1250001",
                "body_bytes_seen": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES + extra,
                "body_bytes_inspected": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES + extra,
                "body_truncated": False,
                "truncated": False,
                "eos_seen": True,
            }
            for kind in ("memory", "file", "mixed")
            for mode, extra in ((kind + "-within", 0), (kind + "-over-limit", 1))
        ]

    @classmethod
    def _telemetry_events(cls) -> list[dict[str, object]]:
        return [
            dict(
                row,
                event=event,
                phase=phase,
                rule_id="",
                body_bytes_seen=(
                    row["body_bytes_seen"] if event != "transaction_cleanup" else 0
                ),
                body_bytes_inspected=(
                    row["body_bytes_inspected"] if event != "transaction_cleanup" else 0
                ),
                eos_seen=event == "phase4_completion",
            )
            for row in cls._positive_events()
            for event, phase in (
                ("phase4_append", "response_body"),
                ("phase4_completion", "response_body"),
                ("transaction_cleanup", "logging"),
            )
        ]

    def test_output_root_rejects_shared_ancestor_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            shared = Path(temporary) / "shared"
            shared.mkdir(mode=0o777)
            shared.chmod(0o777)
            destination = shared / "new-fixture"
            with self.assertRaises(RUNNER_MODULE.FixtureFailure):
                RUNNER_MODULE.require_absolute_directory(destination, "output root", create=True)
            self.assertFalse(destination.exists())
            self.assertEqual(shared.stat().st_mode & 0o777, 0o777)

    def test_output_root_creates_private_leaf_and_preserves_existing_safe_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "new-fixture"
            self.assertEqual(
                RUNNER_MODULE.require_absolute_directory(destination, "output root", create=True),
                destination,
            )
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            destination.chmod(0o750)
            RUNNER_MODULE.require_absolute_directory(destination, "output root", create=True)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o750)

    def test_fixture_configuration_keeps_the_test_module_separate(self) -> None:
        config = (FIXTURE / "config").read_text(encoding="utf-8")
        self.assertIn("ngx_http_body_buffer_fixture_module", config)
        self.assertIn("ngx_http_body_buffer_fixture_module.c", config)
        self.assertIn("ngx_module_type=HTTP_FILTER", config)
        self.assertIn("HTTP_FILTER_MODULES", config)
        self.assertIn("ngx_http_modsecurity_module", config)
        self.assertIn('"$ngx_module_link" = ADDON', config)
        self.assertNotIn("connectors/nginx/src", config)

    def test_native_module_emits_each_required_real_buffer_state(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        for mode in (
            "memory-within",
            "memory-over-limit",
            "file-within",
            "file-over-limit",
            "mixed-within",
            "mixed-over-limit",
            "invalid-metadata",
            "missing-source",
            "read-error",
            "short-read",
            "allocation-failure",
        ):
            self.assertIn(f'"{mode}"', source)
        self.assertIn("buffer->memory = 1", source)
        self.assertIn("buffer->in_file = 1", source)
        self.assertIn("buffer->last_buf = 1", source)
        self.assertIn("buffer->last_in_chain = 1", source)
        self.assertIn("ngx_http_output_filter(r, &output)", source)
        self.assertIn("ngx_http_body_buffer_fixture_body_filter", source)
        self.assertIn("ngx_http_body_buffer_fixture_next_body_filter", source)
        self.assertIn("ngx_http_body_buffer_fixture_init", source)
        self.assertIn("connector-boundary mode=%V", source)
        self.assertIn('representation = "file-only"', source)
        self.assertIn("invalid-metadata", source)
        self.assertIn("missing-source", source)
        self.assertIn("short_file", source)
        self.assertIn("body-buffer-fixture mode=%V", source)
        self.assertIn("body_buffer_fixture_short_file", source)
        self.assertIn("body_buffer_fixture_mixed_file", source)
        self.assertIn("file_length = (off_t) FIXTURE_BODY_LENGTH", source)

    def test_runner_rebuilds_exact_head_modules_and_checks_forwarding(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        ast.parse(source, filename=str(RUNNER))
        self.assertEqual(RUNNER_MODULE.EXPECTED_NGINX_ROOT, "nginx-1.31.6")
        self.assertIn("assert_exact_checkout", source)
        self.assertIn("fixture requires a clean exact checkout", source)
        self.assertIn("pwd.getpwuid(os.geteuid())", source)
        self.assertIn('f"user {nginx_user} {nginx_group};"', source)
        self.assertIn("--add-module=", source)
        self.assertNotIn("--add-dynamic-module=", source)
        self.assertIn("--with-ld-opt=-Wl,--wrap=ngx_pnalloc", source)
        self.assertIn("connectors' / 'nginx", source)
        self.assertIn("nginx_body_buffer_fixture", source)
        self.assertNotIn("ngx_http_modsecurity_module.so", source)
        self.assertIn('if body != b""', source)
        self.assertIn("require_healthy_worker", source)
        self.assertIn("connector_boundary_representation", source)
        self.assertIn("FIXTURE_MIXED_FORWARDED_PAYLOAD", source)
        self.assertIn("forwarding_representation", source)
        self.assertIn('"  sendfile on;"', source)
        self.assertIn("short_body_file", source)
        self.assertIn("mixed_body_file", source)
        self.assertIn("positive_phase4_event_accounting", source)
        self.assertIn('row.get("rule_id") != "1250001"', source)
        self.assertIn('row.get("body_bytes_seen")', source)
        self.assertIn('row.get("eos_seen") is not True', source)
        self.assertIn("phase4_event_log_sha256", source)
        self.assertIn("require_static_fixture_filter_order", source)
        self.assertIn("connector_then_fixture_then_postpone", source)
        self.assertIn("not_representable_on_this_64_bit_off_t_size_t_runtime", source)

    def test_allocation_fault_is_static_fixture_only(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("ngx_http_body_buffer_fixture_fail_allocation", source)
        self.assertIn("ngx_http_body_buffer_fixture_allocation_wrapper_hits", source)
        self.assertIn("volatile sig_atomic_t", source)
        self.assertIn("size == 32768U", source)
        self.assertIn("__wrap_ngx_pnalloc", source)
        self.assertIn("__real_ngx_pnalloc", source)
        self.assertNotIn("setenv(", source)
        self.assertNotIn("getenv(", source)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertNotIn("LD_PRELOAD", runner)
        self.assertIn(
            "test_only_static_ngx_pnalloc_wrap_32768_byte_scratch",
            runner,
        )
        self.assertIn("allocation-wrapper-hits=1", runner)
        product = (source_path('connectors/nginx/src/ngx_http_modsecurity_body_filter.c', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertNotIn("MSCONNECTOR_NGINX_BODY_FIXTURE_FAIL_ALLOC", product)

    def test_positive_event_accounting_is_retained_with_the_rule_binding(self) -> None:
        paths = {
            "/memory-within": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES,
            "/memory-over-limit": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES + 1,
            "/file-within": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES,
            "/file-over-limit": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES + 1,
            "/mixed-within": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES,
            "/mixed-over-limit": RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES + 1,
        }
        events = self._positive_events()
        retained = RUNNER_MODULE.validate_positive_events(events)
        self.assertEqual(set(retained), set(paths))
        self.assertEqual(retained["/mixed-over-limit"]["rule_id"], "1250001")
        self.assertEqual(
            retained["/file-over-limit"]["body_bytes_seen"],
            RUNNER_MODULE.FIXTURE_PAYLOAD_BYTES + 1,
        )

    def test_positive_event_accounting_rejects_a_mixed_file_backing_match_gap(self) -> None:
        events = [
            row for row in self._positive_events()
            if str(row["uri"]).endswith("-within")
        ]
        next(row for row in events if row["uri"] == "/mixed-within")["rule_id"] = ""
        with self.assertRaises(RUNNER_MODULE.FixtureFailure):
            RUNNER_MODULE.validate_positive_events(events)

    def test_positive_events_coexist_with_retained_same_uri_telemetry(self) -> None:
        events = self._positive_events() + self._telemetry_events()
        original = [dict(row) for row in events]
        accounting = RUNNER_MODULE.validate_positive_events(events)
        self.assertEqual(len(accounting), 6)
        self.assertEqual(events, original)

    def test_telemetry_alone_cannot_prove_positive_accounting(self) -> None:
        events = self._telemetry_events()
        with self.assertRaises(RUNNER_MODULE.FixtureFailure):
            RUNNER_MODULE.validate_positive_events(events)

    def test_positive_identity_and_accounting_mismatches_fail(self) -> None:
        for field, value in (
            ("phase", "logging"),
            ("rule_id", "other"),
            ("body_bytes_seen", 0),
            ("body_bytes_seen", True),
            ("body_bytes_inspected", 0),
            ("body_bytes_inspected", True),
            ("eos_seen", False),
            ("eos_seen", 1),
            ("body_truncated", True),
            ("body_truncated", 1),
            ("truncated", True),
            ("truncated", 1),
            ("event", "phase4_append"),
        ):
            with self.subTest(field=field):
                events = self._positive_events()
                events[0][field] = value
                with self.assertRaises(RUNNER_MODULE.FixtureFailure):
                    RUNNER_MODULE.validate_positive_events(events)

    def test_duplicate_or_mismatched_positive_event_fails(self) -> None:
        for mismatch in (False, True):
            with self.subTest(mismatch=mismatch):
                events = self._positive_events()
                duplicate = dict(events[0])
                if mismatch:
                    duplicate["rule_id"] = "other"
                events.append(duplicate)
                with self.assertRaises(RUNNER_MODULE.FixtureFailure):
                    RUNNER_MODULE.validate_positive_events(events)

    def test_configtest_failure_summary_is_bounded_and_classified(self) -> None:
        output = (
            "nginx: [emerg] bind() to 127.0.0.1:45823 failed "
            "(98: Address already in use)\nprivate-fixture-content\n"
        )
        summary = RUNNER_MODULE.configtest_failure_summary(output)
        self.assertRegex(
            summary,
            r"^configtest_output_sha256=[0-9a-f]{64} "
            r"configtest_failure_class=listener_address_in_use$",
        )
        self.assertNotIn("private-fixture-content", summary)

    def test_configtest_failure_classification_handles_known_setup_errors(self) -> None:
        self.assertEqual(
            RUNNER_MODULE.classify_configtest_failure(
                "nginx: [emerg] chown(/tmp/client_body_temp, 65534) failed"
            ),
            "client_body_temp_ownership",
        )
        self.assertEqual(
            RUNNER_MODULE.classify_configtest_failure(
                "nginx: [emerg] open() failed (13: Permission denied)"
            ),
            "permission_denied",
        )
        self.assertEqual(
            RUNNER_MODULE.classify_configtest_failure(
                "nginx: [emerg] unknown directive \"modsecurity\""
            ),
            "unknown_directive",
        )
        self.assertEqual(
            RUNNER_MODULE.classify_configtest_failure("opaque fixture failure"),
            "unclassified",
        )



class NginxArchiveSnapshotSecurityTest(unittest.TestCase):

    @contextmanager
    def _workspace(self):
        with tempfile.TemporaryDirectory(prefix='nginx-archive-snapshot-') as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            snapshots = root / 'snapshots'
            snapshots.mkdir(mode=0o700)
            yield (root, snapshots)

    @staticmethod
    def _archive(path, payload=b'fixture-only-never-execute\n', *, member=None):
        with tarfile.open(path, 'w:gz') as bundle:
            entry = member or tarfile.TarInfo(RUNNER_MODULE.EXPECTED_NGINX_ROOT + '/configure')
            if entry.isreg():
                entry.size = len(payload)
                bundle.addfile(entry, io.BytesIO(payload))
            else:
                bundle.addfile(entry)
        path.chmod(0o600)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _assert_closed(self, descriptors):
        self.assertTrue(descriptors)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    @staticmethod
    def _track_open(descriptors):
        original = os.open

        def tracked(*args, **kwargs):
            descriptor = original(*args, **kwargs)
            descriptors.append(descriptor)
            return descriptor
        return tracked

    def _main_control(self, module, phase):

        class ConfigureBoundaryReached(Exception):
            pass
        with self._workspace() as (root, _snapshots):
            archive = root / 'nginx.tar.gz'
            digest = self._archive(archive)
            connector, include, library, output = (root / part for part in ('connector', 'include', 'lib', 'output'))
            for directory in (connector, include, library, output):
                directory.mkdir(mode=0o700)
            (include / 'modsecurity').mkdir(mode=0o700)
            (include / 'modsecurity/modsecurity.h').write_text('fixture header\n')
            (library / 'libmodsecurity.so').write_text('fixture library\n')
            argv = ['--connector-root', str(connector), '--expected-head', 'a' * 40, '--nginx-archive', str(archive), '--nginx-sha256', digest, '--modsecurity-include', str(include), '--modsecurity-lib', str(library), '--output-root', str(output)]
            if phase == 'p4':
                argv.extend(['--response-body-limit', '1024', '--response-body-limit-action', 'Reject'])

            def stop(arguments, **kwargs):
                self.assertEqual(arguments[0], './configure')
                self.assertEqual((kwargs['cwd'] / 'configure').read_bytes(), b'fixture-only-never-execute\n')
                raise ConfigureBoundaryReached
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(RUNNER_MODULE, 'require_absolute_directory', side_effect=lambda path, label, **kwargs: path))
                stack.enter_context(mock.patch.object(RUNNER_MODULE, 'assert_exact_checkout', return_value='a' * 40))
                stack.enter_context(mock.patch.object(RUNNER_MODULE, 'run', side_effect=stop))
                if phase == 'p3':
                    stack.enter_context(mock.patch.object(module, 'SHARED', RUNNER_MODULE))
                    selected_os = SimpleNamespace(geteuid=lambda: 1000, environ=os.environ, cpu_count=os.cpu_count)
                    stack.enter_context(mock.patch.object(module, 'os', selected_os))
                with self.assertRaises(ConfigureBoundaryReached):
                    module.main(argv)
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), digest)

    def test_archive_snapshot_legitimate_p4_main_uses_verified_snapshot(self):
        self._main_control(RUNNER_MODULE, 'p4')

    def test_archive_snapshot_legitimate_p3_main_uses_shared_snapshot(self):
        self._main_control(P3_RUNNER_MODULE, 'p3')

    def test_archive_snapshot_valid_private_archive_round_trip(self):
        with self._workspace() as (root, snapshots):
            archive = root / 'nginx.tar.gz'
            digest = self._archive(archive)
            destination = root / 'source'
            destination.mkdir(mode=0o700)
            real_open = tarfile.open
            with RUNNER_MODULE.verified_archive_snapshot(archive, digest, snapshots) as (snapshot, observed):
                with mock.patch.object(RUNNER_MODULE.tarfile, 'open', wraps=real_open) as opened:
                    extracted = RUNNER_MODULE.safe_extract(snapshot, destination)
                self.assertIs(opened.call_args.kwargs['fileobj'], snapshot)
                self.assertEqual(observed, digest)
                self.assertEqual((extracted / 'configure').read_bytes(), b'fixture-only-never-execute\n')
            self.assertTrue(snapshot.closed)
            self.assertEqual(list(snapshots.iterdir()), [])

    def test_archive_snapshot_rejects_symlink_leaf_and_ancestor(self):
        for variant in ('symlink-leaf', 'symlink-ancestor'):
            with self.subTest(variant=variant), self._workspace() as (root, snapshots):
                actual = root / 'actual'
                actual.mkdir(mode=0o700)
                archive = actual / 'nginx.tar.gz'
                digest = self._archive(archive)
                if variant == 'symlink-leaf':
                    selected = root / 'alias.tar.gz'
                    selected.symlink_to(archive)
                else:
                    alias = root / 'alias'
                    alias.symlink_to(actual, target_is_directory=True)
                    selected = alias / archive.name
                with self.assertRaises(RUNNER_MODULE.FixtureFailure), RUNNER_MODULE.verified_archive_snapshot(selected, digest, snapshots):
                    self.fail('unsafe source yielded a snapshot')
                self.assertEqual(list(snapshots.iterdir()), [])

    def test_archive_snapshot_rejects_untrusted_ancestor(self):
        with self._workspace() as (root, snapshots):
            shared = root / 'shared'
            shared.mkdir(mode=0o777)
            shared.chmod(0o777)
            archive = shared / 'nginx.tar.gz'
            digest = self._archive(archive)
            with self.assertRaises(RUNNER_MODULE.FixtureFailure), RUNNER_MODULE.verified_archive_snapshot(archive, digest, snapshots):
                self.fail('shared writable ancestry yielded a snapshot')
            self.assertEqual(shared.stat().st_mode & 511, 511)
            self.assertEqual(list(snapshots.iterdir()), [])

    def test_archive_snapshot_rejects_fifo_and_hard_link(self):
        for variant in ('fifo', 'hard-link'):
            with self.subTest(variant=variant), self._workspace() as (root, snapshots):
                archive = root / 'nginx.tar.gz'
                if variant == 'fifo':
                    os.mkfifo(archive, 0o600)
                    digest = '0' * 64
                else:
                    digest = self._archive(archive)
                    os.link(archive, root / 'alias.tar.gz')
                with self.assertRaises(RUNNER_MODULE.FixtureFailure), RUNNER_MODULE.verified_archive_snapshot(archive, digest, snapshots):
                    self.fail('non-regular or linked source yielded a snapshot')
                self.assertTrue(archive.exists())
                self.assertEqual(list(snapshots.iterdir()), [])

    def test_archive_snapshot_rename_after_hash_cannot_replace_extracted_bytes(self):
        with self._workspace() as (root, snapshots):
            archive, replacement = (root / 'nginx.tar.gz', root / 'replacement.tar.gz')
            digest = self._archive(archive, b'approved\n')
            self._archive(replacement, b'replaced-never-execute\n')
            original = hashlib.file_digest

            def after_hash(fileobj, algorithm):
                hashed = original(fileobj, algorithm)
                os.replace(replacement, archive)
                return hashed
            destination = root / 'source'
            destination.mkdir(mode=0o700)
            with mock.patch.object(RUNNER_MODULE.hashlib, 'file_digest', side_effect=after_hash), RUNNER_MODULE.verified_archive_snapshot(archive, digest, snapshots) as (snapshot, observed):
                extracted = RUNNER_MODULE.safe_extract(snapshot, destination)
            self.assertEqual(observed, digest)
            self.assertEqual((extracted / 'configure').read_bytes(), b'approved\n')
            self.assertNotEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), digest)

    def test_archive_snapshot_inplace_change_during_copy_cannot_match_original_hash(self):
        with self._workspace() as (root, snapshots):
            archive = root / 'nginx.tar.gz'
            digest = self._archive(archive)
            original = os.read
            changed = False

            def mutate_after_first_chunk(descriptor, count):
                nonlocal changed
                chunk = original(descriptor, count)
                if chunk and (not changed):
                    changed = True
                    with archive.open('r+b') as source:
                        source.seek(len(chunk))
                        source.write(b'Z' * (archive.stat().st_size - len(chunk)))
                return chunk
            with mock.patch.object(RUNNER_MODULE, '_ARCHIVE_COPY_CHUNK_BYTES', 16), mock.patch.object(RUNNER_MODULE.os, 'read', side_effect=mutate_after_first_chunk), self.assertRaisesRegex(RUNNER_MODULE.FixtureFailure, 'SHA-256 mismatch'), RUNNER_MODULE.verified_archive_snapshot(archive, digest, snapshots):
                self.fail('changed source yielded a snapshot')
            self.assertTrue(changed)
            self.assertEqual(list(snapshots.iterdir()), [])

    def test_archive_snapshot_wrong_digest_never_extracts(self):
        with self._workspace() as (root, snapshots):
            archive = root / 'nginx.tar.gz'
            self._archive(archive)
            descriptors = []
            with mock.patch.object(RUNNER_MODULE.os, 'open', side_effect=self._track_open(descriptors)), self.assertRaisesRegex(RUNNER_MODULE.FixtureFailure, 'SHA-256 mismatch'), RUNNER_MODULE.verified_archive_snapshot(archive, '0' * 64, snapshots):
                self.fail('wrong digest yielded a snapshot')
            self._assert_closed(descriptors)
            self.assertTrue(archive.is_file())
            self.assertEqual(list(snapshots.iterdir()), [])

    def test_archive_snapshot_buffer_failure_closes_owned_descriptors(self):
        with self._workspace() as (root, snapshots):
            archive = root / 'nginx.tar.gz'
            digest = self._archive(archive)
            descriptors = []
            with mock.patch.object(RUNNER_MODULE.os, 'open', side_effect=self._track_open(descriptors)), mock.patch.object(RUNNER_MODULE.io, 'BytesIO', side_effect=OSError('fixture snapshot allocation failure')), self.assertRaises(RUNNER_MODULE.FixtureFailure), RUNNER_MODULE.verified_archive_snapshot(archive, digest, snapshots):
                self.fail('failed wrapper yielded a snapshot')
            self._assert_closed(descriptors)
            self.assertEqual(list(snapshots.iterdir()), [])

    def test_archive_snapshot_partial_copy_failure_closes_snapshot(self):
        with self._workspace() as (root, snapshots):
            archive = root / 'nginx.tar.gz'
            digest = self._archive(archive)
            descriptors = []

            def interrupted(source, snapshot):
                snapshot.write(b'partial')
                raise OSError('fixture partial-copy failure')
            with mock.patch.object(RUNNER_MODULE.os, 'open', side_effect=self._track_open(descriptors)), mock.patch.object(RUNNER_MODULE, '_copy_archive_snapshot', side_effect=interrupted), self.assertRaises(RUNNER_MODULE.FixtureFailure), RUNNER_MODULE.verified_archive_snapshot(archive, digest, snapshots):
                self.fail('partial copy yielded a snapshot')
            self._assert_closed(descriptors)
            self.assertEqual(list(snapshots.iterdir()), [])

    def test_archive_snapshot_short_write_is_rejected_and_closed(self):
        with self._workspace() as (root, snapshots):
            archive = root / 'nginx.tar.gz'
            digest = self._archive(archive)
            original = io.BytesIO
            wrappers = []

            class ShortWriter:

                def __init__(self, stream):
                    self.stream = stream

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    self.close()

                def write(self, chunk):
                    return self.stream.write(chunk[:-1])

                def close(self):
                    self.stream.close()

                @property
                def closed(self):
                    return self.stream.closed

            def short_writer(*args, **kwargs):
                stream = ShortWriter(original(*args, **kwargs))
                wrappers.append(stream)
                return stream
            with mock.patch.object(RUNNER_MODULE.io, 'BytesIO', side_effect=short_writer), self.assertRaisesRegex(RUNNER_MODULE.FixtureFailure, 'copy was incomplete'), RUNNER_MODULE.verified_archive_snapshot(archive, digest, snapshots):
                self.fail('short write yielded a snapshot')
            self.assertTrue(wrappers)
            self.assertTrue(all(stream.closed for stream in wrappers))
            self.assertEqual(list(snapshots.iterdir()), [])

    def test_archive_snapshot_never_uses_a_name_or_removes_foreign_entries(self):
        with self._workspace() as (root, snapshots):
            archive = root / 'nginx.tar.gz'
            digest = self._archive(archive)
            foreign = snapshots / '.nginx-archive-foreign'
            foreign.write_bytes(b'foreign-preserved')
            with mock.patch.object(RUNNER_MODULE.os, 'unlink', side_effect=AssertionError('snapshot must not unlink paths')), RUNNER_MODULE.verified_archive_snapshot(archive, digest, snapshots) as (snapshot, observed):
                self.assertIsInstance(snapshot, io.BytesIO)
                self.assertEqual(observed, digest)
                self.assertEqual(list(snapshots.iterdir()), [foreign])
            self.assertEqual(foreign.read_bytes(), b'foreign-preserved')

    def test_archive_snapshot_rejects_byte_budget_before_or_during_copy(self):
        for variant in ('existing-oversize', 'growth-during-copy'):
            with self.subTest(variant=variant), self._workspace() as (root, snapshots):
                archive = root / 'nginx.tar.gz'
                digest = self._archive(archive)
                limit = 1 if variant == 'existing-oversize' else archive.stat().st_size
                original = RUNNER_MODULE._copy_archive_snapshot

                def grow(source, snapshot, *, archive=archive, original=original):
                    with archive.open('ab') as target:
                        target.write(b'!')
                    original(source, snapshot)
                with ExitStack() as stack:
                    stack.enter_context(mock.patch.object(RUNNER_MODULE, 'MAX_ARCHIVE_BYTES', limit))
                    if variant == 'growth-during-copy':
                        stack.enter_context(mock.patch.object(RUNNER_MODULE, '_copy_archive_snapshot', side_effect=grow))
                    with self.assertRaisesRegex(RUNNER_MODULE.FixtureFailure, 'compressed input byte limit'), RUNNER_MODULE.verified_archive_snapshot(archive, digest, snapshots):
                        self.fail('oversize copy yielded a snapshot')
                self.assertEqual(list(snapshots.iterdir()), [])

    def test_archive_snapshot_preserves_tar_member_denials(self):
        for variant in ('absolute', 'parent', 'symlink', 'hardlink', 'device'):
            with self.subTest(variant=variant), self._workspace() as (root, snapshots):
                member_name = {'absolute': '/absolute', 'parent': '../parent'}.get(variant, 'nginx-1.31.6/member')
                member = tarfile.TarInfo(member_name)
                if variant in {'symlink', 'hardlink'}:
                    member.type = tarfile.SYMTYPE if variant == 'symlink' else tarfile.LNKTYPE
                    member.linkname = 'outside'
                elif variant == 'device':
                    member.type = tarfile.CHRTYPE
                archive = root / 'nginx.tar.gz'
                digest = self._archive(archive, member=member)
                destination = root / 'source'
                destination.mkdir(mode=0o700)
                with RUNNER_MODULE.verified_archive_snapshot(archive, digest, snapshots) as (snapshot, _), self.assertRaisesRegex(RUNNER_MODULE.FixtureFailure, 'unsafe member'):
                    RUNNER_MODULE.safe_extract(snapshot, destination)
                self.assertEqual(list(destination.iterdir()), [])

    def test_archive_extractor_rejects_unverified_path(self):
        with self._workspace() as (root, _snapshots):
            archive = root / 'nginx.tar.gz'
            self._archive(archive)
            with self.assertRaisesRegex(RUNNER_MODULE.FixtureFailure, 'held verified archive snapshot'):
                RUNNER_MODULE.safe_extract(archive, root / 'source')

    def test_archive_snapshot_rejects_unsafe_source_or_snapshot_mode(self):
        for variant in ('writable-source', 'nonprivate-snapshot', 'directory-source'):
            with self.subTest(variant=variant), self._workspace() as (root, snapshots):
                archive = root / 'nginx.tar.gz'
                digest = self._archive(archive)
                if variant == 'writable-source':
                    archive.chmod(0o622)
                elif variant == 'nonprivate-snapshot':
                    snapshots.chmod(0o750)
                else:
                    archive.unlink()
                    archive.mkdir(mode=0o700)
                descriptors = []
                with mock.patch.object(RUNNER_MODULE.os, 'open', side_effect=self._track_open(descriptors)), self.assertRaises(RUNNER_MODULE.FixtureFailure), RUNNER_MODULE.verified_archive_snapshot(archive, digest, snapshots):
                    self.fail('unsafe mode or source type yielded a snapshot')
                self._assert_closed(descriptors)
                self.assertEqual(list(snapshots.iterdir()), [])

    def test_archive_snapshot_requires_no_anonymous_filesystem_support(self):
        with self._workspace() as (root, snapshots):
            archive = root / 'nginx.tar.gz'
            digest = self._archive(archive)
            original = os.open

            def reject_creation(path, flags, *args, **kwargs):
                self.assertFalse(flags & (os.O_CREAT | os.O_EXCL))
                return original(path, flags, *args, **kwargs)
            with mock.patch.object(RUNNER_MODULE.os, 'open', side_effect=reject_creation), mock.patch.object(RUNNER_MODULE.os, 'O_TMPFILE', 0, create=True), RUNNER_MODULE.verified_archive_snapshot(archive, digest, snapshots) as (snapshot, observed):
                self.assertIsInstance(snapshot, io.BytesIO)
                self.assertEqual(observed, digest)
            self.assertEqual(list(snapshots.iterdir()), [])


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
