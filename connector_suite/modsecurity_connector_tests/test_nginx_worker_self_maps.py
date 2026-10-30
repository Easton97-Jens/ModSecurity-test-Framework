"""Actual Root/nobody descriptor capture and strict independent identity checks."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import errno
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = connector_root()
MAPS = load_source(source_path('ci/runtime/lifecycle/nginx-worker-self-maps.py', root=ROOT))
STORAGE = Path('/var/tmp/codex/ModSecurity-conector')

def frame(**overrides):
    raw = b'1000-2000 r-xp 0 00:00 1 /owned/module.so\n'
    header = dict(version=1,pid=2,ppid=1,uid=65534,gid=65534,starttime=123,bytes=len(raw))
    header.update(overrides)
    return json.dumps(header).encode()+b'\n'+raw

class IdentityTests(unittest.TestCase):
    def validate(self, raw, actual=(65534,1,'S','123'), required=('/owned/module.so',)):
        return MAPS.validate(raw,dict(worker_pid=2,master_pid=1),actual,required)
    def test_complete_bound_maps(self):
        self.assertIn(b'/owned/module.so',self.validate(frame()))
    def test_wrong_worker(self):
        raw=frame(pid=3)
        with self.assertRaises(ValueError):self.validate(raw)
    def test_wrong_uid(self):
        raw=frame(uid=0)
        with self.assertRaises(ValueError):self.validate(raw)
    def test_reused_pid(self):
        raw=frame()
        with self.assertRaises(ValueError):self.validate(raw,actual=(65534,1,'S','124'))
    def test_partial_record(self):
        raw=frame()[:-1]
        with self.assertRaises(ValueError):self.validate(raw)
    def test_missing_module(self):
        raw=frame()
        with self.assertRaises(ValueError):self.validate(raw,required=('/different/module.so',))
    def test_wrong_byte_count(self):
        raw=frame(bytes=1)
        with self.assertRaises(ValueError):self.validate(raw)
    def test_missing_identity(self):
        raw=frame()
        with self.assertRaises(ValueError):self.validate(raw,actual=None)

class SetupFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.drivers={}
        for name in ('common-input-fault','lifecycle-sequences'):
            driver = load_source(ROOT / ('ci/runtime/lifecycle/run-nginx-' + name + '.py'))
            cls.drivers[name]=driver
    def test_missing_helper_closes_input_fault_descriptor_before_launch(self):
        driver=self.drivers['common-input-fault']
        with tempfile.TemporaryDirectory(dir=STORAGE) as temporary:
            output=Path(temporary)
            descriptor=os.open(output/'native-fault',os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            args=SimpleNamespace(worker_self_map_library=str(output/'missing.so'))
            prepared=(output,None,{},'a'*32,12345,b'',output/'projection')
            with patch.object(driver,'prepare',return_value=prepared),patch.object(driver,'native_environment',return_value=({},descriptor)),patch.object(driver.subprocess,'Popen') as launching:
                with self.assertRaises((OSError,ValueError)):driver.run(args)
                launching.assert_not_called()
            with self.assertRaises(OSError):os.fstat(descriptor)

    def armed_capture(self, output):
        driver=self.drivers['lifecycle-sequences']
        library=output/'descriptor-fixture.so'
        library.write_bytes(b'private descriptor lifecycle test; never dynamically loaded')
        args=SimpleNamespace(worker_self_map_library=str(library))
        environment={}
        capture=driver.SELF_MAPS.Capture(args,output,environment,{},driver.STARTUP)
        self.assertIsNotNone(capture.descriptor)
        self.addCleanup(capture.close)
        return capture,environment

    def assert_closed(self, descriptor):
        with self.assertRaises(OSError) as error:fcntl.fcntl(descriptor,fcntl.F_GETFD)
        self.assertEqual(error.exception.errno,errno.EBADF)

    def test_capture_fsync_error_closes_real_descriptor_and_clears_identity(self):
        with tempfile.TemporaryDirectory(dir=STORAGE) as temporary:
            capture,_=self.armed_capture(Path(temporary))
            descriptor=capture.descriptor
            with patch.object(os,'fsync',side_effect=OSError('actual injected fsync failure')):
                with self.assertRaisesRegex(OSError,'actual injected fsync failure'):capture.close()
            self.assertIsNone(capture.descriptor)
            self.assert_closed(descriptor)

    def test_capture_close_error_clears_identity_after_actual_kernel_close(self):
        with tempfile.TemporaryDirectory(dir=STORAGE) as temporary:
            capture,_=self.armed_capture(Path(temporary))
            descriptor=capture.descriptor
            original_close=os.close
            def failing_close(value):
                original_close(value)
                raise OSError('close failed after real kernel close')
            with patch.object(os,'close',side_effect=failing_close):
                with self.assertRaisesRegex(OSError,'close failed after real kernel close'):capture.close()
            self.assertIsNone(capture.descriptor)
            self.assert_closed(descriptor)

    def test_missing_real_parser_exec_closes_both_armed_descriptors(self):
        driver=self.drivers['lifecycle-sequences']
        with tempfile.TemporaryDirectory(dir=STORAGE) as temporary:
            output=Path(temporary)
            capture,environment=self.armed_capture(output)
            descriptor=capture.descriptor
            fault=os.open(output/'fault.raw',os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            argv=[str(output/'missing-native-parser')]
            with self.assertRaises(FileNotFoundError):driver.configtest_invocation(output,12345,argv,environment,fault,capture)
            self.assertIsNone(capture.descriptor)
            self.assert_closed(descriptor)
            self.assert_closed(fault)

    def test_real_config_output_write_failure_closes_both_armed_descriptors(self):
        driver=self.drivers['lifecycle-sequences']
        with tempfile.TemporaryDirectory(dir=STORAGE) as temporary:
            output=Path(temporary)
            capture,environment=self.armed_capture(output)
            descriptor=capture.descriptor
            fault=os.open(output/'fault.raw',os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            (output/'configtest.stdout').mkdir()
            with patch.object(driver.BASE,'invoke',return_value=(0,b'actual capture',b'',None)):
                with self.assertRaises(IsADirectoryError):driver.configtest_invocation(output,12345,[],environment,fault,capture)
            self.assertIsNone(capture.descriptor)
            self.assert_closed(descriptor)
            self.assert_closed(fault)

    def test_parser_error_stays_primary_when_capture_sync_cleanup_also_fails(self):
        driver=self.drivers['lifecycle-sequences']
        with tempfile.TemporaryDirectory(dir=STORAGE) as temporary:
            output=Path(temporary)
            capture,environment=self.armed_capture(output)
            descriptor=capture.descriptor
            fault=os.open(output/'fault.raw',os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            argv=[str(output/'missing-native-parser')]
            with patch.object(os,'fsync',side_effect=OSError('secondary cleanup failure')):
                with self.assertRaises(FileNotFoundError) as error:driver.configtest_invocation(output,12345,argv,environment,fault,capture)
            self.assertIn('secondary cleanup failure',str(error.exception.__cause__))
            self.assertIsNone(capture.descriptor)
            self.assert_closed(descriptor)
            self.assert_closed(fault)
    def test_missing_helper_closes_sequence_fault_descriptor(self):
        driver=self.drivers['lifecycle-sequences']
        with tempfile.TemporaryDirectory(dir=STORAGE) as temporary:
            output=Path(temporary)
            descriptor=os.open(output/'native-fault',os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            args=SimpleNamespace(worker_self_map_library=str(output/'missing.so'))
            with self.assertRaises((OSError,ValueError)):driver.prepare_worker_maps(args,output,{}, {},descriptor)
            with self.assertRaises(OSError):os.fstat(descriptor)

HARNESS = r'''
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc,char **argv) {
    if(argc!=2) return 76;
    pid_t child=fork();
    if(child<0) return 75;
    if(child==0) {
        if(setgroups(0,NULL)!=0 || setgid(65534)!=0 || setuid((uid_t)atoi(argv[1]))!=0) _exit(77);
        sleep(3);
        _exit(0);
    }
    printf("%ld\n",(long)child);fflush(stdout);
    int status=0;
    if(waitpid(child,&status,0)<0 || !WIFEXITED(status)) return 74;
    return WEXITSTATUS(status);
}
'''

def maps_nobody():
    return any(int(inside)<=65534<int(inside)+int(count) for inside,_,count in
               (line.split() for line in Path('/proc/self/uid_map').read_text().splitlines()))

@unittest.skipUnless(os.geteuid()==0 and shutil.which('cc') and maps_nobody(), 'actual Root/nobody mapping and existing C compiler required')
class NativeCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='self-maps-',dir=STORAGE)
        cls.directory=Path(cls.temporary.name)
        source=cls.directory/'harness.c';source.write_text(HARNESS)
        common=['rtk','proxy','cc','-std=c17','-D_DEFAULT_SOURCE','-Wall','-Wextra','-Werror']
        subprocess.run(common+[str(source),'-o',str(cls.directory/'harness')],check=True,timeout=30)
        subprocess.run(common+['-fPIC','-shared',str(source_path('tests/fixtures/nginx_worker_self_maps.c', root=ROOT)),'-ldl','-o',str(cls.directory/'capture.so')],check=True,timeout=30)
    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()
    def invoke(self,name,*,mode=0o600,pass_descriptor=True,target='65534',worker='65534',append=True):
        path=self.directory/(name+'.raw')
        descriptor=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|(os.O_APPEND if append else 0),mode)
        os.fchmod(descriptor,mode)
        env=dict(os.environ,LD_PRELOAD=str(self.directory/'capture.so'),MSCONNECTOR_OWNED_SELF_MAP_FD=str(descriptor))
        if target is not None:env['MSCONNECTOR_OWNED_SELF_MAP_UID']=target
        process=subprocess.Popen(['rtk','proxy',str(self.directory/'harness'),worker],env=env,pass_fds=(descriptor,) if pass_descriptor else (),stdout=subprocess.PIPE,text=True)
        try:
            pid=int(process.stdout.readline())
            deadline=time.monotonic()+1
            while True:
                status={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line}
                if status['Uid'].split()[1]==worker:break
                if time.monotonic()>=deadline:self.fail('actual selected worker UID was not observed')
                time.sleep(0.01)
            actual=(int(status['Uid'].split()[1]),int(status['PPid']), 'S',Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19])
            process.wait(timeout=5)
            self.assertEqual(process.returncode,0)
            raw=os.pread(descriptor,MAPS.MAXIMUM+1,0)
            if raw:
                header=json.loads(raw.partition(b'\n')[0])
                return MAPS.validate(raw,dict(worker_pid=pid,master_pid=header['ppid']),actual,[str(self.directory/'capture.so')])
            return raw
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=5)
            process.stdout.close()
            os.close(descriptor)
    def test_real_nobody_reads_own_maps_through_private_fd(self):
        self.assertIn(b'/capture.so',self.invoke('positive'))
    def test_missing_inherited_descriptor_writes_nothing(self):
        self.assertEqual(self.invoke('missing-fd',pass_descriptor=False),b'')
    def test_unsafe_mode_writes_nothing(self):
        self.assertEqual(self.invoke('bad-mode',mode=0o644),b'')
    def test_missing_selected_uid_writes_nothing(self):
        self.assertEqual(self.invoke('missing-uid',target=None),b'')
    def test_wrong_actual_uid_writes_nothing(self):
        self.assertEqual(self.invoke('wrong-uid',worker='65533'),b'')
    def test_missing_append_writes_nothing(self):
        self.assertEqual(self.invoke('missing-append',append=False),b'')


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__=='__main__':unittest.main()
