"""Genuine public SDK multipart collections, physical files, and destruction."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = connector_root()
BUILD = load_source(source_path('ci/runtime/lifecycle/apache-i12/acceptance/build_multipart_observer.py', root=ROOT))
HOST_IO_BUILD = load_source(source_path('ci/runtime/lifecycle/apache-i12/acceptance/build_host_io.py', root=ROOT))

FIXTURE = r'''
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <new>
#include <string>
static int allocation_budget=-1;
void *operator new(std::size_t size) {
    if (allocation_budget==0) throw std::bad_alloc();
    if (allocation_budget>0) --allocation_budget;
    if (void *value=std::malloc(size)) return value;
    throw std::bad_alloc();
}
void operator delete(void *value) noexcept { std::free(value); }
void operator delete(void *value,std::size_t) noexcept { std::free(value); }
static int descriptor_count() {
    DIR *directory=opendir("/proc/self/fd");
    if (!directory) return -1;
    int count=0;
    while (readdir(directory)) ++count;
    closedir(directory); return count;
}
using namespace modsecurity;
extern "C" void i12_apache_observe_multipart(void *) noexcept;
extern "C" void i12_apache_observe_multipart_cleanup(void *) noexcept;
int main(int argc, char **argv) {
    if(argc != 3) return 2;
    auto *engine=msc_init(); auto *rules=msc_create_rules_set(); const char *error=nullptr;
    std::string config="SecRuleEngine On\nSecRequestBodyAccess On\nSecUploadKeepFiles Off\nSecTmpSaveUploadedFiles On\nSecUploadDir ";
    config += argv[1]; config += "\n";
    if(!engine || !rules || msc_rules_add(rules,config.c_str(),&error)<0) { fprintf(stderr,"%s",error?error:"init");return 3; }
    std::string mode=argv[2];
    auto *tx=mode=="quoted-id" ? msc_new_transaction_with_id(engine,rules,"\"\\\x01\x80",nullptr) :
        msc_new_transaction(engine,rules,nullptr); if(!tx)return 4;
    msc_process_connection(tx,"127.0.0.1",1234,"127.0.0.1",8080);
    msc_process_uri(tx,"/_multipart","POST","1.1");
    msc_add_request_header(tx,(const unsigned char *)"Content-Type",(const unsigned char *)"multipart/form-data; boundary=i12proof");
    msc_process_request_headers(tx);
    std::string body="--i12proof\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"synthetic.txt\"\r\nContent-Type: text/plain\r\n\r\nDATA\r\n--i12proof--\r\n";
    if(msc_append_request_body(tx,(const unsigned char *)body.data(),body.size())!=1 || msc_process_request_body(tx)!=1)return 5;
    if(mode=="allocation-failure") {
        int baseline=descriptor_count(); if(baseline<0)return 6;
        for(int budget=0;budget<48;++budget) {
            allocation_budget=budget;errno=E2BIG;i12_apache_observe_multipart(tx);
            int observed_errno=errno;allocation_budget=-1;
            if(observed_errno!=E2BIG || descriptor_count()!=baseline)return 7;
        }
        msc_transaction_cleanup(tx);i12_apache_observe_multipart_cleanup(tx);
        msc_rules_cleanup(rules);msc_cleanup(engine);
        printf("{\"allocation_fault_budgets\":48,\"descriptor_leaks\":0}\n");return 0;
    }
    if(mode=="escape")tx->m_variableFilesTmpNames.set("escape","/etc/passwd",0);
    if(mode=="symlink")tx->m_variableFilesTmpNames.set("symlink",std::string(argv[1])+"/foreign-link",0);
    if(mode=="limit")for(int i=0;i<20;++i)tx->m_variableFilesTmpNames.set(std::to_string(i),"/outside/"+std::to_string(i),0);
    if(mode=="null") {
        errno=E2BIG; i12_apache_observe_multipart(nullptr); int before=errno;
        msc_transaction_cleanup(tx);errno=ENOTTY;i12_apache_observe_multipart_cleanup(tx);
        int after=errno;msc_rules_cleanup(rules);msc_cleanup(engine);
        printf("{\"observe_errno\":%d,\"cleanup_errno\":%d}\n",before,after);return 0;
    }
    errno=E2BIG; i12_apache_observe_multipart(tx); int before=errno;
    auto *key=tx; msc_transaction_cleanup(tx);
    errno=ENOTTY;i12_apache_observe_multipart_cleanup(key); int after=errno;
    // Repetition must neither dereference a destroyed transaction nor emit another row.
    i12_apache_observe_multipart_cleanup(key);
    msc_rules_cleanup(rules);msc_cleanup(engine);
    printf("{\"observe_errno\":%d,\"cleanup_errno\":%d}\n",before,after);return 0;
}
'''

PASSIVE_FIXTURE = r'''
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/stat.h>
using namespace modsecurity;
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    auto *engine = msc_init(); auto *rules = msc_create_rules_set(); const char *error = nullptr;
    std::string config = "SecRuleEngine On\nSecRequestBodyAccess On\nSecUploadKeepFiles Off\n"
        "SecTmpSaveUploadedFiles On\nSecUploadDir ";
    config += argv[1]; config += "\n";
    if (!engine || !rules || msc_rules_add(rules, config.c_str(), &error) < 0) {
        std::fprintf(stderr, "%s", error ? error : "init"); return 3;
    }
    auto *tx = msc_new_transaction(engine, rules, nullptr); if (!tx) return 4;
    if (msc_process_connection(tx, "127.0.0.1", 1234, "127.0.0.1", 8080) != 1 ||
        msc_process_uri(tx, "/_multipart_passive", "POST", "1.1") != 1) return 5;
    msc_add_request_header(tx, reinterpret_cast<const unsigned char *>("Content-Type"),
        reinterpret_cast<const unsigned char *>("multipart/form-data; boundary=i12passive"));
    if (msc_process_request_headers(tx) != 1) return 6;
    std::string body = "--i12passive\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"synthetic.txt\"\r\n"
        "Content-Type: text/plain\r\n\r\nDATA\r\n--i12passive--\r\n";
    if (msc_append_request_body(tx, reinterpret_cast<const unsigned char *>(body.data()), body.size()) != 1) return 7;
    errno = E2BIG; int body_result = msc_process_request_body(tx); int body_errno = errno;
    if (body_result != 1 || tx->m_variableFilesTmpNames.size() != 1) return 8;
    std::string path;
    for (const auto &entry : tx->m_variableFilesTmpNames) if (entry.second) path = entry.second->getValue();
    struct stat before = {}; int before_result = path.empty() ? -1 : lstat(path.c_str(), &before);
    int before_errno = before_result ? errno : 0;
    std::string id = tx->m_id; void *key = tx;
    errno = ENOTTY; msc_transaction_cleanup(tx); int cleanup_errno = errno;
    struct stat after = {}; int after_result = path.empty() ? -1 : lstat(path.c_str(), &after);
    int after_errno = after_result ? errno : 0;
    msc_rules_cleanup(rules); msc_cleanup(engine);
    std::printf("{\"body_result\":%d,\"body_errno\":%d,\"cleanup_errno\":%d,"
        "\"transaction_id\":\"%s\",\"transaction_key\":\"%p\",\"tmpnames_count\":1,"
        "\"before_result\":%d,\"before_errno\":%d,\"before_size\":%lld,\"before_uid\":%u,"
        "\"after_result\":%d,\"after_errno\":%d}\n", body_result, body_errno, cleanup_errno,
        id.c_str(), key, before_result, before_errno, static_cast<long long>(before.st_size),
        static_cast<unsigned>(before.st_uid), after_result, after_errno);
    return 0;
}
'''


class ApacheMultipartObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = Path(os.environ.get("CODEX_TEST_TMP_ROOT", "/var/tmp/codex/ModSecurity-conector"))
        temporary = tempfile.TemporaryDirectory(prefix="apache-multipart-sdk-", dir=base)
        cls.addClassCleanup(temporary.cleanup)
        cls.work = Path(temporary.name)
        include = Path(os.environ.get("MODSECURITY_INCLUDE_DIR", "/usr/include"))
        cls.build = BUILD.build(cls.work / "build", include)
        source = cls.work / "fixture.cpp"
        source.write_text(FIXTURE)
        library = os.environ.get("MODSECURITY_LIB_FILE", "/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3.0.14")
        headers = [] if include.resolve() == Path("/usr/include") else ["-isystem", str(include)]
        cls.binary = cls.work / "fixture"
        command = ["rtk", "proxy", "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", *headers,
                   str(source), str(cls.work / "build/apache-multipart-observer.o"), library,
                   "-pthread", "-o", str(cls.binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=90)
        if compiled.returncode:
            raise RuntimeError(compiled.stderr)
        cls.evidence = os.environ.get("I12_APACHE_MULTIPART_EVIDENCE_DIR")
        if cls.evidence:
            destination = Path(cls.evidence)
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination / source.name)
            shutil.copy2(cls.binary, destination / cls.binary.name)
            shutil.copytree(cls.work / "build", destination / "build", dirs_exist_ok=True)
            (destination / "fixture-build.json").write_text(json.dumps({"command": command,
                "exit": compiled.returncode, "stderr": compiled.stderr, "observer": cls.build,
                "fixture_sha256": hashlib.sha256(cls.binary.read_bytes()).hexdigest(),
                "selected_sdk_library": str(Path(library).resolve()),
                "selected_sdk_library_sha256": hashlib.sha256(Path(library).read_bytes()).hexdigest()}, indent=2))

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="case-", dir=self.work)
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.directory.chmod(0o700)
        marker = self.directory / "multipart.enable"
        marker.write_text("I12_APACHE_MULTIPART_V1\n")
        marker.chmod(0o600)

    def tearDown(self):
        if self.evidence:
            destination = Path(self.evidence) / self._testMethodName
            destination.mkdir(exist_ok=True)
            for path in self.directory.iterdir():
                if path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1:
                    shutil.copy2(path, destination / path.name)

    def run_native(self, mode="normal", admitted=True, root=None):
        environment = os.environ.copy()
        environment.pop("I12_APACHE_MULTIPART_ROOT", None)
        if admitted:
            environment["I12_APACHE_MULTIPART_ROOT"] = str(root or self.directory)
        started_ns = time.monotonic_ns()
        result = subprocess.run(["rtk", "proxy", str(self.binary), str(self.directory), mode],
            env=environment, capture_output=True, text=True, timeout=15)
        completed_ns = time.monotonic_ns()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"observe_errno": 7, "cleanup_errno": 25})
        (self.directory / "process.json").write_text(json.dumps({"exit": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}, indent=2))
        path = self.directory / "multipart.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1 else []
        for row in rows:
            self.assertLessEqual(started_ns, row["monotonic_ns"])
            self.assertLessEqual(row["monotonic_ns"], completed_ns)
        return rows

    def test_real_sdk_collection_file_and_actual_destructor_unlink(self):
        before, after = self.run_native()
        self.assertEqual(before["files_count"], 1)
        self.assertEqual(before["files_names_count"], 1)
        self.assertEqual(before["files_sizes_count"], 1)
        self.assertEqual(len(before["filename_fingerprints"]), 1)
        self.assertEqual(len(before["filename_fingerprints"][0]["value_fingerprint_fnv1a64"]), 16)
        self.assertEqual(before["filename_fingerprints"][0]["value_fingerprint_fnv1a64"], "33ce5792db0608ae")
        self.assertTrue(before["filename_fingerprints_complete"])
        self.assertEqual(before["files_combined_size"], "4")
        self.assertEqual(before["native_tmpfile_objects_count"], 1)
        self.assertEqual(before["files_tmpnames_count"], 1)
        self.assertTrue(before["files"][0]["exists"])
        self.assertTrue(before["files"][0]["regular"])
        self.assertEqual(before["files"][0]["size"], 4)
        self.assertEqual(before["files"][0]["uid"], os.geteuid())
        self.assertTrue(before["path_snapshot_complete"])
        self.assertEqual(before["transaction_id"], after["transaction_id"])
        self.assertTrue(before["transaction_id"])
        self.assertEqual(before["transaction_key"], after["transaction_key"])
        self.assertLess(before["monotonic_ns"], after["monotonic_ns"])
        self.assertFalse(after["dead_transaction_dereferenced"])
        self.assertFalse(after["files"][0]["exists"])
        self.assertEqual(after["files"][0]["stat_errno"], 2)
        self.assertEqual(before["files"][0]["path_fingerprint_fnv1a64"], after["files"][0]["path_fingerprint_fnv1a64"])

    def test_absent_optin_does_not_change_sdk_processing_or_leave_uploaded_file(self):
        self.assertEqual(self.run_native(admitted=False), [])
        self.assertEqual(sorted(path.name for path in self.directory.iterdir()), ["multipart.enable", "process.json"])

    def test_json_quoting_preserves_control_and_high_bytes(self):
        before, after = self.run_native("quoted-id")
        for row in (before, after):
            self.assertEqual(row["transaction_id"], '"\\\x01\x80')

    def test_allocation_exceptions_close_descriptors_and_preserve_errno(self):
        environment = os.environ.copy()
        environment["I12_APACHE_MULTIPART_ROOT"] = str(self.directory)
        result = subprocess.run(["rtk", "proxy", str(self.binary), str(self.directory), "allocation-failure"],
            env=environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"allocation_fault_budgets": 48, "descriptor_leaks": 0})
        self.assertIn("apache-multipart-observer: observation failed", result.stderr)

    def test_invalid_marker_and_public_root_are_refused(self):
        (self.directory / "multipart.enable").write_text("wrong\n")
        self.assertEqual(self.run_native(), [])
        (self.directory / "multipart.enable").write_text("I12_APACHE_MULTIPART_V1\n")
        self.directory.chmod(0o755)
        self.assertEqual(self.run_native(), [])

    def test_parent_escape_is_not_statted(self):
        before, after = self.run_native("escape")
        for row in (before, after):
            excluded = [item for item in row["files"] if not item["direct_private_child"]]
            self.assertEqual(len(excluded), 1)
            self.assertIsNone(excluded[0]["exists"])
            self.assertIsNone(excluded[0]["stat_errno"])

    def test_symlink_metadata_does_not_follow_foreign_target(self):
        target = self.work / "retained"
        target.write_bytes(b"retained")
        (self.directory / "foreign-link").symlink_to(target)
        before, _ = self.run_native("symlink")
        links = [item for item in before["files"] if item.get("symlink")]
        self.assertEqual(len(links), 1)
        self.assertFalse(links[0]["regular"])
        self.assertEqual(target.read_bytes(), b"retained")

    def test_output_symlink_hardlink_and_root_alias_are_refused(self):
        target = self.work / "output-retained"
        target.write_bytes(b"retained")
        output = self.directory / "multipart.jsonl"
        output.symlink_to(target)
        self.assertEqual(self.run_native(), [])
        self.assertEqual(target.read_bytes(), b"retained")
        output.unlink()
        os.link(target, output)
        self.assertEqual(self.run_native(), [])
        self.assertEqual(target.read_bytes(), b"retained")
        output.unlink()
        alias = self.work / "root-alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        self.assertEqual(self.run_native(root=alias), [])

    def test_path_limit_is_reported_as_incomplete_not_silent_success(self):
        before, after = self.run_native("limit")
        self.assertEqual(before["files_tmpnames_count"], 21)
        self.assertEqual(len(before["files"]), 16)
        self.assertFalse(before["path_snapshot_complete"])
        self.assertFalse(after["path_snapshot_complete"])

    def test_null_and_unobserved_destroyed_transaction_emit_no_observation(self):
        self.assertEqual(self.run_native("null"), [])

    def test_output_size_budget_does_not_overwrite_or_append(self):
        output = self.directory / "multipart.jsonl"
        original = b"x" * (1024 * 1024)
        output.write_bytes(original)
        output.chmod(0o600)
        environment = os.environ.copy()
        environment["I12_APACHE_MULTIPART_ROOT"] = str(self.directory)
        result = subprocess.run(["rtk", "proxy", str(self.binary), str(self.directory), "normal"],
            env=environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"observe_errno": 7, "cleanup_errno": 25})
        self.assertEqual(output.read_bytes(), original)

    def test_marker_symlink_and_hardlink_do_not_admit_observation(self):
        marker = self.directory / "multipart.enable"
        target = self.work / "foreign-marker"
        target.write_text("I12_APACHE_MULTIPART_V1\n")
        target.chmod(0o600)
        marker.unlink()
        marker.symlink_to(target)
        self.assertEqual(self.run_native(), [])
        marker.unlink()
        os.link(target, marker)
        self.assertEqual(self.run_native(), [])


class ApacheMultipartPassiveHostIOIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = Path(os.environ.get("CODEX_TEST_TMP_ROOT", "/var/tmp/codex/ModSecurity-conector"))
        temporary = tempfile.TemporaryDirectory(prefix="apache-multipart-passive-", dir=base)
        cls.addClassCleanup(temporary.cleanup)
        cls.work = Path(temporary.name)
        cls.include = Path(os.environ.get("MODSECURITY_INCLUDE_DIR", "/usr/include"))
        multipart = BUILD.build(cls.work / "multipart-build", cls.include)
        cls.receipt = HOST_IO_BUILD.build(cls.work / "combined-build", cls.include,
            cls.work / "multipart-build/apache-multipart-observer.o")
        cls.observer = cls.work / "combined-build/apache-host-io.so"
        source = cls.work / "passive-fixture.cpp"
        source.write_text(PASSIVE_FIXTURE)
        # The fixture contains only public SDK calls; callbacks live solely in
        # the preloaded combined observer image.
        if "i12_apache_observe_multipart" in PASSIVE_FIXTURE:
            raise AssertionError("passive SDK fixture must not name observer callbacks")
        library = Path(os.environ.get("MODSECURITY_LIB_FILE",
            "/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3.0.14"))
        headers = [] if cls.include.resolve() == Path("/usr/include") else ["-isystem", str(cls.include)]
        cls.binary = cls.work / "passive-fixture"
        command = ["rtk", "proxy", "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", *headers,
            str(source), str(library), "-Wl,-rpath," + str(library.parent), "-pthread", "-o", str(cls.binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=90)
        if compiled.returncode:
            raise RuntimeError(compiled.stderr)
        cls.build_evidence = {"command": command, "exit": compiled.returncode,
            "fixture_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "fixture_binary_sha256": hashlib.sha256(cls.binary.read_bytes()).hexdigest(),
            "multipart_build": multipart, "combined_build": cls.receipt}
        evidence = os.environ.get("I12_APACHE_MULTIPART_EVIDENCE_DIR")
        if evidence:
            destination = Path(evidence) / "passive-host-io-integration"
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination / source.name)
            shutil.copy2(cls.binary, destination / cls.binary.name)
            shutil.copy2(cls.observer, destination / cls.observer.name)
            shutil.copytree(cls.work / "multipart-build", destination / "multipart-build", dirs_exist_ok=True)
            shutil.copytree(cls.work / "combined-build", destination / "combined-build", dirs_exist_ok=True)
            (destination / "fixture-build.json").write_text(json.dumps(cls.build_evidence, indent=2) + "\n")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="case-", dir=self.work)
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.directory.chmod(0o700)
        marker = self.directory / "multipart.enable"
        marker.write_text("I12_APACHE_MULTIPART_V1\n")
        marker.chmod(0o600)

    def run_passive(self, *, preload: bool, opt_in: bool) -> tuple[dict, list[dict]]:
        environment = os.environ.copy()
        environment.pop("I12_APACHE_MULTIPART_ROOT", None)
        environment.pop("I12_APACHE_IO_ROOT", None)
        environment.pop("LD_PRELOAD", None)
        if preload:
            environment["LD_PRELOAD"] = str(self.observer)
        if opt_in:
            environment["I12_APACHE_MULTIPART_ROOT"] = str(self.directory)
        completed = subprocess.run(["rtk", "proxy", str(self.binary), str(self.directory)], env=environment,
            capture_output=True, text=True, timeout=20)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        rows_path = self.directory / "multipart.jsonl"
        rows = [json.loads(line) for line in rows_path.read_text().splitlines()] if rows_path.is_file() else []
        return json.loads(completed.stdout), rows

    def test_real_sdk_calls_trigger_passive_observation_and_preserve_results(self):
        symbols = subprocess.run(["rtk", "proxy", "nm", "-D", str(self.observer)],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(symbols.returncode, 0, symbols.stderr)
        self.assertRegex(symbols.stdout, r"(?m)^\S+ T i12_apache_observe_multipart$")
        self.assertRegex(symbols.stdout, r"(?m)^\S+ T i12_apache_observe_multipart_cleanup$")
        self.assertEqual(self.receipt["multipart_object_sha256"],
            self.build_evidence["multipart_build"]["object_sha256"])
        control, control_rows = self.run_passive(preload=False, opt_in=False)
        self.assertEqual(control_rows, [])
        observed, rows = self.run_passive(preload=True, opt_in=True)
        self.assertEqual(len(rows), 2)
        before, after = rows
        for field in ("body_result", "body_errno", "cleanup_errno", "tmpnames_count",
                      "before_result", "before_errno", "before_size", "before_uid",
                      "after_result", "after_errno"):
            self.assertEqual(observed[field], control[field], field)
        self.assertEqual(observed["body_result"], 1)
        self.assertEqual(observed["before_result"], 0)
        self.assertEqual(observed["before_size"], 4)
        self.assertEqual(observed["before_uid"], os.geteuid())
        self.assertEqual(observed["after_result"], -1)
        self.assertEqual(observed["after_errno"], 2)
        self.assertEqual([row["kind"] for row in rows],
            ["native_multipart_after_request_body", "native_multipart_after_actual_cleanup"])
        self.assertEqual(before["transaction_id"], observed["transaction_id"])
        self.assertEqual(after["transaction_id"], observed["transaction_id"])
        self.assertEqual(before["transaction_key"], observed["transaction_key"])
        self.assertEqual(after["transaction_key"], observed["transaction_key"])
        self.assertLess(before["monotonic_ns"], after["monotonic_ns"])
        self.assertTrue(before["files"][0]["exists"])
        self.assertFalse(after["files"][0]["exists"])
        self.assertFalse(after["dead_transaction_dereferenced"])

    def test_combined_image_without_multipart_opt_in_is_transparent(self):
        control, _ = self.run_passive(preload=False, opt_in=False)
        observed, rows = self.run_passive(preload=True, opt_in=False)
        self.assertEqual(rows, [])
        for field in ("body_result", "body_errno", "cleanup_errno", "tmpnames_count",
                      "before_result", "before_errno", "before_size", "before_uid",
                      "after_result", "after_errno"):
            self.assertEqual(observed[field], control[field], field)

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
