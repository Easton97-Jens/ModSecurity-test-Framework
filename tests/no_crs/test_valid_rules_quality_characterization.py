"""Characterize error precedence and raw-byte strictness before refactoring."""
import json
import unittest

from tests.no_crs import test_valid_rules_file_receipt as receipt_tests


class ValidRulesQualityCharacterization(unittest.TestCase):
    setUp = receipt_tests.ValidRulesFileReceiptTest.setUp
    unit_bundle = receipt_tests.ValidRulesFileReceiptTest.unit_bundle

    def captures(self, record):
        bundle = self.root / record["artifacts"]["configtest_dir"]
        return receipt_tests.contract.configtest_bundle_captures(record, bundle)

    def test_existing_successful_raw_probe_is_accepted(self):
        record = self.unit_bundle()
        self.assertIsNone(receipt_tests.contract.validate_valid_rules_probe(record, self.captures(record)))

    def test_typed_roles_and_cleanup_keep_exact_rejection_messages(self):
        for leaf, key, replacement, message in (
                ("roles.json", "master_uid", False, "valid rules raw roles must observe distinct root master/nobody worker"),
                ("roles.json", "worker_pid", True, "valid rules raw roles must observe distinct root master/nobody worker"),
                ("cleanup.json", "verified", 1, "valid rules raw cleanup must bind and retire its actual processes/listener")):
            with self.subTest(leaf=leaf, key=key):
                record = self.unit_bundle()
                captures = self.captures(record)
                value = json.loads(captures[leaf])
                value[key] = replacement
                captures[leaf] = json.dumps(value).encode()
                with self.assertRaisesRegex(receipt_tests.contract.ContractError, "^" + message + "$"):
                    receipt_tests.contract.validate_valid_rules_probe(record, captures)

    def test_invalid_native_metadata_precedes_foreign_run_and_ambiguity(self):
        record = self.unit_bundle()
        captures = self.captures(record)
        event = json.loads(captures["phase1-events.jsonl"])
        event["connector"] = "apache"
        event["run_id"] = "foreign"
        captures["phase1-events.jsonl"] = json.dumps(event).encode()
        with self.assertRaisesRegex(receipt_tests.contract.ContractError, "^valid rules retained native event has invalid metadata$"):
            receipt_tests.contract.validate_valid_rules_probe(record, captures)

    def test_valid_rules_diagnostic_path_error_precedes_raw_probe_error(self):
        record = self.unit_bundle()
        bundle = self.root / record["artifacts"]["configtest_dir"]
        captures = self.captures(record)
        captures["stderr.log"] = b"syntax is ok\ntest is successful\n"
        captures["request-result.json"] = b'{"operation":"foreign"}'
        with self.assertRaisesRegex(receipt_tests.contract.ContractError, "^valid rules configtest lacks its exact successful native diagnostic$"):
            receipt_tests.contract.validate_configtest_bundle_template(record, bundle, captures, canonical=True)


if __name__ == "__main__":
    unittest.main()
