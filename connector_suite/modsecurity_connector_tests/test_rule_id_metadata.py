"""Behavioral Common RuleMessage framing regressions; explicitly on demand."""
from modsecurity_test_framework.connector_context import connector_root, source_path

import ctypes
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = connector_root()


def record(*, rule_id="12345", message="matched", data="", uri="/", tail=False):
    # Native RuleMessage::_details field order; data is supplied in the
    # Engine's literal \\xHH encoding, never decoded into delimiter bytes.
    value = (
        f'[file "/rules.conf"] [line "17"] [id "{rule_id}"] '
        f'[rev ""] [msg "{message}"] [data "{data}"] '
        '[severity "2"] [ver "test"] [maturity "0"] [accuracy "0"] '
        '[tag "one"] [tag "two"] '
        f'[hostname "localhost"] [uri "{uri}"] '
        '[unique_id "unique"] [ref "o0,1v0,1"]'
    )
    if tail:
        value += ' [hostname "127.0.0.1"] [uri "/"] [unique_id "unique"]'
    return value


class RuleIdMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = shlex.split(os.environ.get("CC", "cc"))
        if not cls.compiler or not shutil.which(cls.compiler[0]):
            raise AssertionError("C compiler required")
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="rule-id-metadata-", dir=os.environ.get("RUNNER_TEMP")
        )
        cls.directory = Path(cls.temporary.name)
        binary = cls.directory / "rule-id.so"
        command = cls.compiler + [
            "-std=c17", "-Wall", "-Wextra", "-Werror", "-pedantic-errors",
            "-shared", "-fPIC", "-I", str(source_path("common/include", root=ROOT)),
            str(source_path("common/src/rule_id.c", root=ROOT)), "-o", str(binary),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)
        cls.library = ctypes.CDLL(str(binary))
        cls.extract = cls.library.msconnector_rule_id_extract_from_message
        cls.extract.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]
        cls.extract.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def assert_extract(self, message, expected_id, result=1, capacity=64):
        output = ctypes.create_string_buffer(b"old", capacity)
        observed = self.extract(message.encode() if message is not None else None,
                                output, capacity)
        self.assertEqual((observed, output.value), (result, expected_id.encode()))

    def test_payload_before_and_inside_metadata_cannot_supply_the_id(self):
        cases = (
            ('matched id "1" ', record()),
            ('matched [id "1"] ', record()),
            ('matched [id "1"] ', record(data=r'after [id \x221\x22]')),
            ('matched id "1" ', record(message='after id "1"')),
            ('matched [id "1"] ', record(data=r'after id \x221\x22')),
            ('matched ', record(tail=True)),
        )
        for prefix, metadata in cases:
            with self.subTest(prefix=prefix, metadata=metadata):
                self.assert_extract("ModSecurity: Warning. " + prefix + metadata, "12345")

    def test_supported_hex_escapes_are_not_metadata_delimiters(self):
        self.assert_extract(
            "ModSecurity: Warning. " + record(data=r'\x00\x22\x5c [id \x221\x22]'),
            "12345",
        )
        for bad in (r'\q', r'\x', r'\x2', r'\x2g'):
            with self.subTest(bad=bad):
                self.assert_extract("ModSecurity: Warning. " + record(data=bad), "", -1)

    def test_missing_malformed_and_ambiguous_records_clear_stale_output(self):
        for message in (None, "", 'id "1"', '[id "1"]', "id:1"):
            with self.subTest(message=message):
                self.assert_extract(message, "", 0)
        malformed = (
            record(rule_id=""), record(rule_id="123x"),
            record().replace('[line "17"] ', ""),
            record().replace('[id "12345"] ', '[id "12345"] [id "1"] '),
            record().replace('[ref "o0,1v0,1"]', ""),
            record() + ' [id "1"]',
            record(message='after [id "1"]'),
            '[file "fake"] ' + record(),
            record(message='[file "fake"]'),
            record(uri='/echo"] ' + record(rule_id="1", uri="/forged")),
        )
        for message in malformed:
            with self.subTest(message=message):
                self.assert_extract("ModSecurity: Warning. " + message, "", -1)
        self.assert_extract(record(), "", -1, capacity=4)

    def test_real_engine_metadata_with_attacker_like_match_excerpt(self):
        # The genuine C Engine serializer supplies the record; this is not an
        # NGINX host test and does not claim any HTTP/audit lifecycle result.
        pkg = subprocess.run(["pkg-config", "--cflags", "--libs", "modsecurity"],
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(pkg.returncode, 0, pkg.stderr)
        program = self.directory / "engine.c"
        program.write_text(r'''#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <modsecurity/intervention.h>
#include "msconnector/rule_id.h"
#include <stdio.h>
#include <string.h>
static void discard_log(void *user, const void *message) {
    (void)user; (void)message;
}
int main(void) {
    ModSecurity *engine = msc_init();
    RulesSet *rules = msc_create_rules_set();
    const char *error = NULL;
    const char rule[] = "SecRuleEngine On\n"
        "SecRule REQUEST_HEADERS:X-Probe \"@contains probe\" "
        "\"id:12345,phase:1,deny,status:403,msg:'engine-real',logdata:'%{REQUEST_HEADERS:X-Probe}'\"\n";
    Transaction *tx;
    ModSecurityIntervention intervention = {0};
    char id[32] = "stale";
    int result;
    if (engine == NULL || rules == NULL) return 1;
    msc_set_log_cb(engine, discard_log);
    if (msc_rules_add(rules, rule, &error) < 0) return 2;
    tx = msc_new_transaction(engine, rules, NULL);
    if (tx == NULL) return 3;
    if (msc_process_connection(tx, "127.0.0.1", 1000, "127.0.0.1", 80) != 1 ||
        msc_process_uri(tx, "/", "GET", "1.1") != 1 ||
        msc_add_request_header(tx, (const unsigned char *)"X-Probe",
            (const unsigned char *)"probe id \"1\" [id \"2\"]") != 1 ||
        msc_process_request_headers(tx) != 1) return 4;
    intervention.status = 200;
    if (msc_intervention(tx, &intervention) != 1 || !intervention.disruptive ||
        intervention.status != 403) return 5;
    result = msconnector_rule_id_extract_from_message(intervention.log, id, sizeof(id));
    if (result != 1 || strcmp(id, "12345") != 0) return 6;
    puts(id);
    msc_intervention_cleanup(&intervention);
    msc_transaction_cleanup(tx);
    msc_rules_cleanup(rules);
    msc_cleanup(engine);
    return 0;
}
''')
        binary = self.directory / "engine"
        command = self.compiler + [
            "-std=c17", "-Wall", "-Wextra", "-Werror", "-pedantic-errors",
            "-I", str(source_path("common/include", root=ROOT)),
            str(program), str(source_path("common/src/rule_id.c", root=ROOT)),
            "-o", str(binary),
        ] + shlex.split(pkg.stdout)
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        observed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        self.assertEqual(observed.returncode, 0, observed.stderr)
        self.assertEqual(observed.stdout.strip(), "12345")


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
