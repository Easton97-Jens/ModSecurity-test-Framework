"""Real loopback/APR/SDK controls for the Apache-only physical boundary observer."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
import hashlib
import shutil
import errno
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import unittest

ROOT = connector_root()
BUILD = load_source(source_path('ci/runtime/lifecycle/apache-i12/acceptance/build_host_io.py', root=ROOT))

FIXTURE = r'''
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <apr_general.h>
#include <apr_network_io.h>
#include <apr_portable.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int native_buffer(const char *mode) {
    errno=E2BIG; ModSecurity *engine=msc_init(); int init_errno=errno;
    if(!engine)return 30;
    if(!strcmp(mode,"native-init-only")) {
        printf("{\"init_errno\":%d,\"engine_key\":\"%p\",\"sdk_who_am_i\":\"%s\"}\n",
            init_errno,(void *)engine,msc_who_am_i(engine));msc_cleanup(engine);return 0;
    }
    RulesSet *rules=msc_create_rules_set(); const char *error=NULL;
    const char *action=strstr(mode,"partial")?"ProcessPartial":"Reject";
    char config[1024];
    snprintf(config,sizeof(config),"SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\n"
        "SecRequestBodyLimit 16\nSecRequestBodyNoFilesLimit 16\nSecRequestBodyLimitAction %s\n"
        "SecResponseBodyLimit 16\nSecResponseBodyLimitAction %s\nSecResponseBodyMimeType text/plain\n",action,action);
    if(!rules || msc_rules_add(rules,config,&error)<0)return 31;
    Transaction *tx=msc_new_transaction(engine,rules,NULL);if(!tx)return 32;
    if(msc_process_connection(tx,"127.0.0.1",1234,"127.0.0.1",8080)!=1 ||
        msc_process_uri(tx,"/_buffer","POST","1.1")!=1)return 33;
    msc_add_request_header(tx,(const unsigned char *)"Content-Type",(const unsigned char *)"text/plain");
    if(msc_process_request_headers(tx)!=1)return 34;
    const unsigned char body[]="0123456789ABCDEFG";
    int response=strstr(mode,"response")!=NULL;
    if(response) {
        if(msc_process_request_body(tx)!=1)return 35;
        const char *mime=strstr(mode,"mime")?"image/png":"text/plain";
        msc_add_response_header(tx,(const unsigned char *)"Content-Type",(const unsigned char *)mime);
        if(msc_process_response_headers(tx,200,"HTTP/1.1")!=1)return 36;
    }
    size_t before=response?msc_get_response_body_length(tx):msc_get_request_body_length(tx);
    errno=E2BIG; int result=response?msc_append_response_body(tx,body,17):msc_append_request_body(tx,body,17);
    int saved=errno;size_t after=response?msc_get_response_body_length(tx):msc_get_request_body_length(tx);
    printf("{\"result\":%d,\"before\":%zu,\"after\":%zu,\"errno\":%d}\n",result,before,after,saved);
    msc_transaction_cleanup(tx);msc_rules_cleanup(rules);msc_cleanup(engine);return 0;
}
static int native(const char *mode) {
    ModSecurity *engine=msc_init(); RulesSet *rules=msc_create_rules_set(); const char *error=NULL;
    const char *text="SecRuleEngine On\n"
        "SecAction \"id:120001,phase:1,pass,log,msg:'early benign'\"\n"
        "SecRule REQUEST_URI \"@streq /_sink\" \"id:120016,phase:1,deny,status:403,log,msg:'target'\"\n";
    if(!engine || !rules || msc_rules_add(rules,text,&error)<0)return 20;
    Transaction *transaction=msc_new_transaction(engine,rules,NULL); if(!transaction)return 21;
    if(msc_process_connection(transaction,"127.0.0.1",1234,"127.0.0.1",8080)!=1)return 22;
    if(msc_process_uri(transaction,!strcmp(mode,"native-deny")?"/_sink":"/_healthy","GET","1.1")!=1)return 23;
    if(msc_process_request_headers(transaction)!=1)return 24;
    ModSecurityIntervention intervention={0};intervention.status=200;
    int result=msc_intervention(transaction,&intervention); int saved=errno;
    printf("{\"native_result\":%d,\"status\":%d,\"disruptive\":%d,\"errno\":%d}\n",result,intervention.status,intervention.disruptive,saved);
    free(intervention.url); free(intervention.log);
    msc_transaction_cleanup(transaction);msc_rules_cleanup(rules);msc_cleanup(engine);return 0;
}
int main(int argc,char **argv) {
    if(argc<2)return 2;
    const char *mode=argv[1];
    if(!strcmp(mode,"native-init-only") || !strncmp(mode,"native-buffer-",14))return native_buffer(mode);
    if(!strncmp(mode,"native-",7))return native(mode);
    signal(SIGPIPE,SIG_IGN);
    if(apr_initialize()!=APR_SUCCESS)return 3;
    apr_pool_t *pool=NULL;if(apr_pool_create(&pool,NULL)!=APR_SUCCESS)return 4;
    int listener=socket(AF_INET,SOCK_STREAM,0);if(listener<0)return 5;
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    if(bind(listener,(struct sockaddr *)&address,sizeof(address))!=0 || listen(listener,1)!=0)return 6;
    socklen_t length=sizeof(address);if(getsockname(listener,(struct sockaddr *)&address,&length)!=0)return 7;
    printf("%u\n",ntohs(address.sin_port));fflush(stdout);
    int fd=accept(listener,NULL,NULL);if(fd<0)return 8;
    apr_socket_t *stream=NULL;apr_os_sock_t raw=fd;
    if(apr_os_sock_put(&stream,&raw,pool)!=APR_SUCCESS)return 9;
    const char first[]="HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\nX-Test: synthetic\r\n\r\n";
    const char second[]="HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    int repetitions=!strcmp(mode,"keepalive")?2:1;
    for(int iteration=0;iteration<repetitions;++iteration) {
        char request[2048]; apr_size_t received=sizeof(request);
        if(!strcmp(mode,"peek") && recv(fd,request,sizeof(request),MSG_PEEK)<=0)return 14;
        if(apr_socket_recv(stream,request,&received)!=APR_SUCCESS || received==0)return 10;
        apr_status_t result;apr_size_t written=0;
        if(iteration) { written=sizeof(second)-1;result=apr_socket_send(stream,second,&written); }
        else if(!strcmp(mode,"partial")) {
            written=11;result=apr_socket_send(stream,first,&written);
            if(result!=APR_SUCCESS)return 11;
            struct iovec v[2]={{(void *)(first+11),sizeof(first)-1-11},{"DATA",4}};
            result=apr_socket_sendv(stream,v,2,&written);
        } else if(!strcmp(mode,"sendfile")) {
            apr_file_t *file=NULL; const char *path=getenv("I12_SOCKET_FIXTURE_BODY");
            if(!path || apr_file_open(&file,path,APR_READ,APR_OS_DEFAULT,pool)!=APR_SUCCESS)return 13;
            struct iovec head={(void *)first,sizeof(first)-1};
            apr_hdtr_t hdtr={.headers=&head,.numheaders=1};apr_off_t offset=0;written=4;
            result=apr_socket_sendfile(stream,file,&hdtr,&offset,&written,0);
            apr_file_close(file);
        } else if(!strcmp(mode,"chunked")) {
            const char chunked[]="HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nDATA\r\n0\r\n\r\n";
            written=sizeof(chunked)-1;result=apr_socket_send(stream,chunked,&written);
        } else if(!strcmp(mode,"fail")) {
            if(shutdown(fd,SHUT_WR)!=0)return 12;
            written=sizeof(first)-1;result=apr_socket_send(stream,first,&written);
        } else if(!strcmp(mode,"zero")) {
            written=0;result=apr_socket_send(stream,first,&written);
        } else {
            struct iovec v[2]={{(void *)first,sizeof(first)-1},{"DATA",4}};
            result=apr_socket_sendv(stream,v,2,&written);
        }
        printf("{\"apr_status\":%d,\"reported_bytes\":%zu,\"errno\":%d}\n",result,(size_t)written,errno);fflush(stdout);
    }
    apr_socket_close(stream);close(listener);apr_pool_destroy(pool);apr_terminate();return 0;
}
'''

class ApachePhysicalHostIOTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = Path(os.environ.get("CODEX_TEST_TMP_ROOT", os.environ.get("RUNNER_TEMP",
            "/var/tmp/codex/ModSecurity-conector")))
        temporary = tempfile.TemporaryDirectory(prefix="apache-host-io-", dir=base)
        cls.addClassCleanup(temporary.cleanup)
        cls.work = Path(temporary.name)
        include = Path(os.environ.get("MODSECURITY_INCLUDE_DIR", "/usr/include"))
        cls.receipt = BUILD.build(cls.work / "build", include)
        cls.observer = cls.work / "build/apache-host-io.so"
        source = cls.work / "fixture.c"
        source.write_text(FIXTURE)
        def apr(*flags):
            return shlex.split(subprocess.run(["rtk", "proxy", "apr-1-config", *flags],
                check=True, capture_output=True, text=True).stdout)
        cls.binary = cls.work / "fixture"
        accessor = cls.work / "existing-sdk-accessor.o"
        # Leave the compiler's default system include search untouched. An
        # explicit selected SDK tree is third-party code, not project source.
        sdk_headers = [] if include.resolve() == Path("/usr/include") else ["-isystem", str(include)]
        accessor_command = ["rtk", "proxy", "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
            *sdk_headers, "-fPIC", "-c", str(source_path('ci/runtime/lifecycle/native-lifecycle-sdk.cpp', root=ROOT)),
            "-o", str(accessor)]
        accessor_result = subprocess.run(accessor_command, capture_output=True, text=True)
        if accessor_result.returncode:
            raise RuntimeError(accessor_result.stderr)
        library = os.environ.get("MODSECURITY_LIB_FILE", "/usr/lib/x86_64-linux-gnu/libmodsecurity.so")
        command = ["rtk", "proxy", "cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-I", str(include),
            *apr("--includes", "--cppflags", "--cflags"), str(source), str(accessor), "-lstdc++", "-rdynamic", library,
            "-Wl,-rpath," + str(Path(library).parent), *apr("--link-ld", "--libs"), "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
        cls.evidence = os.environ.get("I12_APACHE_HOST_IO_EVIDENCE_DIR")
        if cls.evidence:
            destination = Path(cls.evidence)
            destination.mkdir(parents=True, exist_ok=True)
            for item in (source, cls.binary, cls.observer, accessor):
                shutil.copy2(item, destination / item.name)
            (destination / "fixture-build.json").write_text(json.dumps({
                "command": command, "exit": result.returncode, "stderr": result.stderr,
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "binary_sha256": hashlib.sha256(cls.binary.read_bytes()).hexdigest(),
                "existing_accessor_command": accessor_command,
                "observer_build": cls.receipt}, indent=2))

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="case-", dir=self.work)
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.directory.chmod(0o700)
        (self.directory / "host-io.enable").write_bytes(b"I12_APACHE_HOST_IO_V1\n")
        (self.directory / "host-io.enable").chmod(0o600)

    def tearDown(self):
        if self.evidence:
            destination = Path(self.evidence) / self._testMethodName
            destination.mkdir(exist_ok=True)
            for item in self.directory.iterdir():
                if item.is_file() and not item.is_symlink() and item.stat().st_nlink == 1:
                    shutil.copy2(item, destination / item.name)

    def environment(self, admitted=True):
        env = os.environ.copy()
        env["LD_PRELOAD"] = str(self.observer)
        body = self.directory / "body.bin"
        body.write_bytes(b"DATA")
        env["I12_SOCKET_FIXTURE_BODY"] = str(body)
        if admitted:
            env["I12_APACHE_IO_ROOT"] = str(self.directory)
        else:
            env.pop("I12_APACHE_IO_ROOT", None)
        return env

    def records(self):
        path = self.directory / "host-io.jsonl"
        if not path.exists() or path.is_symlink() or path.stat().st_nlink != 1:
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def run_server(self, mode, *, admitted=True):
        process = subprocess.Popen(["rtk", "proxy", str(self.binary), mode], env=self.environment(admitted),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        port = int(process.stdout.readline())
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            client.sendall(b"GET /_main HTTP/1.1\r\nHost: localhost\r\n\r\n")
            expected = b"DATA" if mode not in ("zero", "fail") else None
            wire = b""
            while expected and not wire.endswith(expected):
                part = client.recv(4096)
                if not part:
                    break
                wire += part
            if mode == "keepalive":
                client.sendall(b"GET /_neighbor HTTP/1.1\r\nHost: localhost\r\n\r\n")
                while not wire.endswith(b"OK"):
                    part = client.recv(4096)
                    if not part:
                        break
                    wire += part
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, stderr)
        (self.directory / "client-wire.bin").write_bytes(wire)
        (self.directory / "fixture-returns.json").write_text(stdout)
        (self.directory / "fixture-stderr.txt").write_text(stderr)
        return wire, [json.loads(line) for line in stdout.splitlines()], self.records()

    def test_actual_apr_sendv_and_client_bytes_agree(self):
        wire, returns, records = self.run_server("sendv")
        self.assertTrue(wire.startswith(b"HTTP/1.1 500"))
        apr = [r for r in records if r.get("function") == "apr_socket_sendv"]
        self.assertEqual(len(apr), 1)
        self.assertEqual(apr[0]["result"], returns[0]["apr_status"])
        self.assertEqual(apr[0]["reported_bytes"], len(wire))
        self.assertTrue(apr[0]["real_symbol_object"])
        headers = [r for r in records if r["kind"] == "response_headers_sent"]
        self.assertEqual([(r["http_status"], r["request_uri"], r["request_sequence"]) for r in headers], [(500, "/_main", 1)])
        self.assertTrue(all(not r["invalid"] for r in records))

    def test_split_actual_header_bytes_require_later_successful_send(self):
        wire, _, records = self.run_server("partial")
        self.assertTrue(wire.endswith(b"DATA"))
        headers = [r for r in records if r["kind"] == "response_headers_sent"]
        self.assertEqual(len(headers), 1)
        first_send = next(r for r in records if r.get("function") == "apr_socket_send")
        self.assertLess(first_send["monotonic_ns"], headers[0]["monotonic_ns"])

    def test_failed_send_has_real_error_and_no_wire_commit(self):
        _, returns, records = self.run_server("fail")
        self.assertEqual(returns[0]["apr_status"], errno.EPIPE)
        apr = next(r for r in records if r.get("function") == "apr_socket_send")
        self.assertEqual(apr["result"], returns[0]["apr_status"])
        self.assertFalse(apr["written_bytes_known"])
        self.assertEqual(apr["errno_at_return"], returns[0]["errno"])
        self.assertFalse(any(r["kind"] == "response_headers_sent" for r in records))

    def test_zero_send_does_not_prove_commit(self):
        _, returns, records = self.run_server("zero")
        self.assertEqual(returns[0]["reported_bytes"], 0)
        self.assertFalse(any(r["kind"] == "response_headers_sent" for r in records))

    def test_peek_does_not_invent_a_second_consumed_request(self):
        _, _, records = self.run_server("peek")
        self.assertEqual(len([r for r in records if r["kind"] == "request_headers_received"]), 1)
        peek = next(r for r in records if r.get("function") == "recv")
        self.assertFalse(peek["stream_accounted_here"])
        header = next(r for r in records if r["kind"] == "response_headers_sent")
        self.assertEqual(header["request_sequence"], 1)

    def test_actual_apr_sendfile_return_and_client_bytes(self):
        wire, returns, records = self.run_server("sendfile")
        self.assertTrue(wire.startswith(b"HTTP/1.1 500"))
        self.assertTrue(wire.endswith(b"DATA"))
        sendfile = next(r for r in records if r.get("function") == "apr_socket_sendfile")
        self.assertEqual(sendfile["result"], returns[0]["apr_status"])
        self.assertEqual(sendfile["reported_bytes"], returns[0]["reported_bytes"])
        self.assertFalse(sendfile["stream_accounted_here"])
        # Header bytes are observed at the real nested APR/libc write boundary.
        header = next(r for r in records if r["kind"] == "response_headers_sent")
        self.assertEqual(header["http_status"], 500)

    def test_chunked_header_commit_keeps_body_framing_explicitly_unsupported(self):
        _, _, records = self.run_server("chunked")
        header = next(r for r in records if r["kind"] == "response_headers_sent")
        self.assertEqual(header["http_status"], 200)
        self.assertFalse(header["body_framing_supported"])
        self.assertIsNone(header["renderer_identity"])

    def test_unix_sockets_are_not_claimed_as_loopback_tcp_wire(self):
        command = ["rtk", "proxy", "python3", "-c",
            "import socket; a,b=socket.socketpair(); a.sendall(b'HTTP/1.1 500 X\\r\\nContent-Length: 0\\r\\n\\r\\n'); b.recv(1024); a.close(); b.close()"]
        result = subprocess.run(command, env=self.environment(), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(r["kind"] == "transport_return" for r in self.records()))

    def test_keepalive_request_sequence_and_uris_are_distinct(self):
        _, _, records = self.run_server("keepalive")
        headers = [r for r in records if r["kind"] == "response_headers_sent"]
        self.assertEqual([(r["http_status"], r["request_uri"], r["request_sequence"]) for r in headers],
            [(500, "/_main", 1), (200, "/_neighbor", 2)])
        self.assertEqual(len({r["socket_inode"] for r in headers}), 1)

    def test_missing_opt_in_forwards_without_observation(self):
        wire, _, records = self.run_server("sendv", admitted=False)
        self.assertTrue(wire.endswith(b"DATA"))
        self.assertEqual(records, [])

    def test_invalid_marker_and_public_directory_refuse_observation(self):
        (self.directory / "host-io.enable").write_text("wrong\n")
        self.assertEqual(self.run_server("sendv")[2], [])
        (self.directory / "host-io.enable").write_text("I12_APACHE_HOST_IO_V1\n")
        self.directory.chmod(0o755)
        self.assertEqual(self.run_server("sendv")[2], [])

    def test_output_symlink_and_hardlink_refuse_without_touching_foreign_file(self):
        target = self.work / "foreign"
        target.write_bytes(b"retained\n")
        output = self.directory / "host-io.jsonl"
        output.symlink_to(target)
        self.run_server("sendv")
        self.assertEqual(target.read_bytes(), b"retained\n")
        output.unlink()
        os.link(target, output)
        self.run_server("sendv")
        self.assertEqual(target.read_bytes(), b"retained\n")
        output.unlink()

    def test_real_native_rule120016_separate_from_early_benign_rule(self):
        process = subprocess.run(["rtk", "proxy", str(self.binary), "native-deny"], env=self.environment(),
            capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        observed = [r for r in self.records() if r["kind"] == "native_intervention_return"]
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["result"], result["native_result"])
        self.assertEqual(observed[0]["native_status"], 403)
        self.assertEqual(observed[0]["native_log_rule_id"], 120016)
        self.assertEqual(observed[0]["phase"], 1)
        created = next(r for r in self.records() if r["kind"] == "native_transaction_created")
        self.assertEqual(created["transaction_id_source"], "sdk_public_m_id")
        self.assertTrue(created["transaction_id"])
        self.assertEqual(created["transaction_id"], observed[0]["transaction_id"])
        self.assertEqual(created["transaction_key"], observed[0]["transaction_key"])
        self.assertIn("ModSecurity", created["sdk_version"])
        self.assertFalse(observed[0]["raw_log_captured"])

    def test_benign_native_rule_does_not_invent_disruptive_output(self):
        process = subprocess.run(["rtk", "proxy", str(self.binary), "native-allow"], env=self.environment(),
            capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        observed = next(r for r in self.records() if r["kind"] == "native_intervention_return")
        self.assertEqual(observed["result"], 0)
        self.assertIsNone(observed["native_log_rule_id"])
        self.assertIsNone(observed["native_status"])

    def run_native_control(self, mode):
        process = subprocess.run(["rtk", "proxy", str(self.binary), mode], env=self.environment(),
            capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        (self.directory / (mode + "-returns.json")).write_text(process.stdout)
        (self.directory / (mode + "-stderr.txt")).write_text(process.stderr)
        return json.loads(process.stdout)

    def test_short_lived_sdk_init_records_real_caller_and_image_without_transaction(self):
        result = self.run_native_control("native-init-only")
        rows = [row for row in self.records() if row['kind'] == 'native_engine_init_return']
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(row['result_nonnull'])
        self.assertEqual(row['engine_key'], result['engine_key'])
        self.assertEqual(row['errno_at_return'], result['init_errno'])
        self.assertEqual(row['sdk_who_am_i'], result['sdk_who_am_i'])
        self.assertIn('ModSecurity', row['sdk_who_am_i'])
        self.assertEqual(Path(row['actual_caller_image']['image']).resolve(), self.binary)
        self.assertIn('libmodsecurity.so', row['real_sdk_image']['image'])
        for key in ('real_sdk_image', 'actual_caller_image'):
            image = row[key]
            metadata = Path(image['image']).stat()
            self.assertEqual((image['device'], image['inode'], image['size']),
                             (metadata.st_dev, metadata.st_ino, metadata.st_size))
        self.assertFalse(any(row['kind'] == 'native_transaction_created' for row in self.records()))

    def test_actual_public_sdk_buffer_lengths_and_exact_return_forwarding(self):
        modes = [('request-partial', 16), ('request-reject', 0), ('response-partial', 16),
                 ('response-reject', 0), ('response-mime', 0)]
        for mode, expected_length in modes:
            with self.subTest(mode=mode):
                result = self.run_native_control('native-buffer-' + mode)
                rows = [row for row in self.records() if row['kind'] == 'native_body_append_return']
                row = rows[-1]
                self.assertEqual(row['sdk_body_length_before'], result['before'])
                self.assertEqual(row['sdk_body_length_after'], result['after'])
                self.assertEqual(row['sdk_body_length_after'], expected_length)
                self.assertEqual(row['input_size'], 17)
                self.assertEqual(row['result'], result['result'])
                self.assertEqual(row['errno_at_return'], result['errno'])
                self.assertEqual(row['transaction_id_source'], 'sdk_public_m_id')
                self.assertTrue(row['transaction_id'])
                created = next(item for item in reversed(self.records())
                               if item['kind'] == 'native_transaction_created')
                self.assertEqual(row['transaction_key'], created['transaction_key'])
                self.assertEqual(row['transaction_id'], created['transaction_id'])
                self.assertEqual(row['phase'], 4 if mode.startswith('response') else 2)
                self.assertTrue(row['phase_is_append_boundary_not_process_execution'])
                control = subprocess.run(['rtk', 'proxy', str(self.binary), 'native-buffer-' + mode],
                    env=self.environment(admitted=False), capture_output=True, text=True, timeout=10)
                self.assertEqual(control.returncode, 0, control.stderr)
                self.assertEqual(json.loads(control.stdout), result)

    def test_ordinary_fixture_500_has_actual_stack_but_no_apache_renderer(self):
        _, _, records = self.run_server('sendv')
        stacks = [row for row in records if row['kind'] == 'outgoing_return_stack']
        self.assertTrue(stacks)
        for row in stacks:
            self.assertTrue(row['frames'])
            self.assertGreater(row['captured_depth'], 0)
            self.assertIsNone(row['renderer_identity'])
        headers = [row for row in records if row['kind'] == 'response_headers_sent']
        self.assertEqual(headers[0]['http_status'], 500)
        self.assertIsNone(headers[0]['renderer_identity'])

    def assert_invalid_iovec_preserves_real_efault(self, operation):
        # ctypes' RTLD_DEFAULT lookup reaches the observer when admitted. The
        # kernel, rather than a stub, rejects address 1 as an iovec array.
        code = """
import ctypes, errno, json, socket, sys
listener = socket.socket()
listener.bind(('127.0.0.1', 0))
listener.listen(1)
peer = socket.create_connection(listener.getsockname(), timeout=5)
stream, _ = listener.accept()
peer.sendall(b'x')
libc = ctypes.CDLL(None, use_errno=True)
operation = getattr(libc, sys.argv[1])
operation.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
operation.restype = ctypes.c_ssize_t
ctypes.set_errno(errno.E2BIG)
result = operation(stream.fileno(), ctypes.c_void_p(1), 1)
saved = ctypes.get_errno()
print(json.dumps({'result': result, 'errno': saved}))
stream.close()
peer.close()
listener.close()
"""
        for admitted in (False, True):
            with self.subTest(admitted=admitted):
                command = ["rtk", "proxy", "python3", "-c", code, operation]
                completed = subprocess.run(command, env=self.environment(admitted),
                    capture_output=True, text=True, timeout=10)
                (self.directory / (operation + "-" + str(admitted) + "-process.json")).write_text(json.dumps({
                    "command": command, "exit": completed.returncode,
                    "stdout": completed.stdout, "stderr": completed.stderr}, indent=2))
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(json.loads(completed.stdout), {"result": -1, "errno": errno.EFAULT})
                if admitted:
                    rows = [row for row in self.records() if row.get('function') == operation]
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]['result'], -1)
                    self.assertEqual(rows[0]['errno_at_return'], errno.EFAULT)
                    self.assertFalse(rows[0]['written_bytes_known'])
                    self.assertIsNone(rows[0]['requested_bytes'])
                    self.assertFalse(rows[0]['stream_accounted_here'])

    def test_real_failed_writev_never_dereferences_invalid_iovec_after_return(self):
        self.assert_invalid_iovec_preserves_real_efault('writev')

    def test_real_failed_readv_never_dereferences_invalid_iovec_after_return(self):
        self.assert_invalid_iovec_preserves_real_efault('readv')

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
