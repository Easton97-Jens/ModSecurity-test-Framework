"""Characterize actual path fixture checks, not native runtime evidence."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.no_crs.test_configtest_artifacts import contract


class ConfigtestPathFixtureQualityTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix='fixture-quality-')
        self.addCleanup(temporary.cleanup)
        self.bundle = Path(temporary.name)

    def record(self, case_id: str) -> dict:
        leaf, state = contract.CONFIGTEST_PATH_FIXTURES[case_id]
        receipt = {'fixture_leaf': leaf, 'fixture_state': state}
        if state == 'regular':
            data = (contract.FRAMEWORK_ROOT / 'tests/fixtures/no-crs-baseline' / leaf).read_bytes()
            path = self.bundle / leaf
            path.write_bytes(data)
            path.chmod(0o600)
            receipt['fixture_sha256'] = hashlib.sha256(data).hexdigest()
        elif state == 'directory':
            (self.bundle / leaf).mkdir(mode=0o700)
        return {'case_id': case_id, 'configtest_receipt': receipt}

    def validate(self, record: dict) -> None:
        contract.validate_configtest_path_fixture(record, self.bundle)

    def test_closed_states_and_unrelated_empty_receipt(self) -> None:
        for case_id in contract.CONFIGTEST_PATH_FIXTURES:
            with self.subTest(case_id=case_id):
                self.validate(self.record(case_id))
        self.validate({'case_id': 'unrelated', 'configtest_receipt': {}})

    def test_receipt_and_closed_identity_errors_precede_filesystem_access(self) -> None:
        examples = [({}, 'configuration receipt is missing'),
                    ({'case_id': 'unrelated', 'configtest_receipt': {'fixture_sha256': 'x'}},
                     'configuration receipt has an unrelated path fixture'),
                    ({'case_id': 'missing_rules_file', 'configtest_receipt': {}},
                     'configuration fixture observation does not match the closed case')]
        with patch.object(contract, 'open_directory_chain') as opening:
            for record, message in examples:
                with self.subTest(message=message):
                    with self.assertRaisesRegex(contract.ContractError, '^' + message + '$'):
                        self.validate(record)
            opening.assert_not_called()

    def test_absent_leaf_rejects_even_dangling_symlink(self) -> None:
        record = self.record('missing_rules_file')
        leaf = self.bundle / record['configtest_receipt']['fixture_leaf']
        leaf.symlink_to(self.bundle / 'nonexistent')
        with self.assertRaisesRegex(contract.ContractError, '^missing rules fixture leaf must remain absent$'):
            self.validate(record)

    def test_regular_bytes_and_digest_independently_rejected(self) -> None:
        for change in ('bytes', 'digest'):
            with self.subTest(change=change):
                record = self.record('phase4_invalid_scope_file')
                if change == 'bytes':
                    (self.bundle / record['configtest_receipt']['fixture_leaf']).write_bytes(b'changed')
                else:
                    record['configtest_receipt']['fixture_sha256'] = '0' * 64
                with self.assertRaisesRegex(contract.ContractError,
                                           '^removed API fixture differs from its exact source bytes/digest$'):
                    self.validate(record)

    def test_regular_metadata_each_predicate_is_required(self) -> None:
        record = self.record('phase4_invalid_scope_file')
        actual = (self.bundle / record['configtest_receipt']['fixture_leaf']).stat()
        for field, value in [('st_mode', 0o040600), ('st_mode', 0o100644),
                             ('st_uid', os.geteuid() + 1), ('st_nlink', 2), ('st_size', 513)]:
            info = SimpleNamespace(**{name: getattr(actual, name)
                                      for name in ('st_mode', 'st_uid', 'st_nlink', 'st_size')})
            setattr(info, field, value)
            with self.subTest(field=field, value=value), patch.object(contract.os, 'fstat', return_value=info):
                with self.assertRaisesRegex(contract.ContractError,
                                           '^removed API fixture must be an owned single-link private regular file$'):
                    self.validate(record)

    def test_regular_open_uses_nofollow_and_nonblock_and_closes_both_fds_on_failure(self) -> None:
        record = self.record('phase4_invalid_scope_file')
        record['configtest_receipt']['fixture_sha256'] = '0' * 64
        original_open, original_close = os.open, os.close
        opened, closed = [], []

        def opening(path, flags, *args, **kwargs):
            descriptor = original_open(path, flags, *args, **kwargs)
            opened.append((path, flags, descriptor))
            return descriptor

        def closing(descriptor):
            closed.append(descriptor)
            original_close(descriptor)

        with patch.object(contract.os, 'open', side_effect=opening), patch.object(contract.os, 'close', side_effect=closing):
            with self.assertRaises(contract.ContractError):
                self.validate(record)
        leaf_open = next(item for item in opened if item[0] == record['configtest_receipt']['fixture_leaf'])
        self.assertTrue(leaf_open[1] & os.O_NOFOLLOW)
        self.assertTrue(leaf_open[1] & os.O_NONBLOCK)
        # Ancestor traversal legitimately reuses descriptor numbers.
        self.assertEqual(closed[-2:], [leaf_open[2], opened[-2][2]])

    def test_regular_symlink_is_not_followed(self) -> None:
        record = self.record('phase4_invalid_scope_file')
        path = self.bundle / record['configtest_receipt']['fixture_leaf']
        path.rename(self.bundle / 'target')
        path.symlink_to(self.bundle / 'target')
        with self.assertRaises(OSError):
            self.validate(record)

    def test_directory_digest_mode_contents_and_owner_are_rejected(self) -> None:
        record = self.record('unsafe_event_path')
        path = self.bundle / record['configtest_receipt']['fixture_leaf']
        record['configtest_receipt']['fixture_sha256'] = '0' * 64
        with self.assertRaisesRegex(contract.ContractError, '^absent/directory fixtures must not claim regular-file bytes$'):
            self.validate(record)
        del record['configtest_receipt']['fixture_sha256']
        for mode in (0o755, 0o700):
            path.chmod(mode)
            if mode == 0o700:
                (path / 'content').touch()
            with self.assertRaisesRegex(contract.ContractError,
                                       '^unsafe event fixture must remain an owned empty private directory$'):
                self.validate(record)
        (path / 'content').unlink()
        actual = path.stat()
        info = SimpleNamespace(st_mode=actual.st_mode, st_uid=os.geteuid() + 1)
        with patch.object(contract.os, 'fstat', return_value=info):
            with self.assertRaises(contract.ContractError):
                self.validate(record)

    def test_directory_symlink_is_not_followed(self) -> None:
        record = self.record('unsafe_event_path')
        path = self.bundle / record['configtest_receipt']['fixture_leaf']
        path.rename(self.bundle / 'directory-target')
        path.symlink_to(self.bundle / 'directory-target', target_is_directory=True)
        with self.assertRaises(OSError):
            self.validate(record)
