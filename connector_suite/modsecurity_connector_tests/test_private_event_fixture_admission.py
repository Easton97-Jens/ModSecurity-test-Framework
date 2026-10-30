"""Bounded native fixture admission/cleanup controls, independent of host runtime."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from modsecurity_test_framework.connector_context import connector_root, source_path

ROOT = connector_root()
BASE_VARIANTS = (
    "private0700-positive",
    "symlink-base-reject-before-mutation",
    "shared0777-base-reject-before-mutation",
    "relative-base-reject-before-mutation",
)
CLEANUP_VARIANTS = (
    "normal-cleanup-positive",
    "named-root-renamed-and-replaced-by-symlink-preserves-foreign-sentinel",
)
COMMON_SOURCES = (
    "event.c",
    "event_jsonl.c",
    "json_escape.c",
    "status.c",
    "http_status.c",
    "transaction_state.c",
)
PROBE = r"""#define main original_fixture_main
#include @FIXTURE@
#undef main
#include <dirent.h>
static int descriptor_count(void) {
    DIR *stream=opendir("/proc/self/fd");
    struct dirent *entry;
    int count=0;
    if (!stream) return -1;
    while ((entry=readdir(stream)) != NULL) {
        if (entry->d_name[0]!='.') ++count;
    }
    if (closedir(stream)!=0) return -1;
    return count;
}
int main(int argc,char **argv) {
    private_event_file_test_paths paths;
    int initial=descriptor_count();
    if (argc!=4 || initial<0) return 2;
    int initialized=initialize_test_paths(argv[2],&paths);
    int swapped=strcmp(argv[1],"named-root-renamed-and-replaced-by-symlink-preserves-foreign-sentinel")==0;
    if (initialized==1 && strncmp(argv[1],"private0700",11)!=0) {
        if (!setup_test_directories(&paths)) return 3;
        int event=openat(paths.private_fd,"events.jsonl",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
        if (event<0 || close(event)!=0) return 4;
        if (swapped && (renameat(paths.base_fd,paths.root_name,paths.base_fd,"held-run")!=0 ||
            symlinkat(argv[3],paths.base_fd,paths.root_name)!=0)) return 5;
    }
    int cleaned=cleanup_test_paths(&paths);
    int final=descriptor_count();
    printf("{\"initialized\":%d,\"cleaned\":%d,\"descriptor_delta\":%d}\n",initialized,cleaned,final-initial);
    return 0;
}
"""


class PrivateEventFixtureAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="private-event-admission-", dir=os.environ["RUNNER_TEMP"]
        )
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.work = Path(cls.temporary.name)
        cls.binary = cls.work / "probe"
        source = cls.work / "probe.c"
        fixture = source_path("tests/private_event_file_smoke.c", root=ROOT)
        source.write_text(PROBE.replace("@FIXTURE@", json.dumps(str(fixture))))
        command = [
            "cc",
            "-std=c17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I" + str(source_path("common/include", root=ROOT)),
            str(source),
        ]
        command += [
            str(source_path("common/src", root=ROOT) / name) for name in COMMON_SOURCES
        ]
        subprocess.run(
            command + ["-o", str(cls.binary)],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )

    def probe(self, variant: str, base: Path, foreign: Path, cwd: Path) -> dict:
        result = subprocess.run(
            [str(self.binary), variant, str(base), str(foreign)],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return json.loads(result.stdout)

    def test_fixture_base_admission(self) -> None:
        for variant in BASE_VARIANTS:
            with (
                self.subTest(variant=variant),
                tempfile.TemporaryDirectory(dir=self.work) as temporary,
            ):
                root = Path(temporary)
                physical = root / "private"
                physical.mkdir(mode=0o700)
                base = physical
                if variant == "symlink-base-reject-before-mutation":
                    base = root / "alias"
                    base.symlink_to(physical, target_is_directory=True)
                elif variant == "shared0777-base-reject-before-mutation":
                    physical.chmod(0o777)
                elif variant == "relative-base-reject-before-mutation":
                    base = Path("private")
                before = sorted(root.iterdir())
                observed = self.probe(variant, base, root / "unused", root)
                self.assertEqual(
                    observed,
                    {
                        "initialized": 1 if variant == "private0700-positive" else -1,
                        "cleaned": 1,
                        "descriptor_delta": 0,
                    },
                )
                self.assertEqual(sorted(root.iterdir()), before)
                self.assertEqual(list(physical.iterdir()), [])

    def test_fixture_cleanup_bound_to_open_root(self) -> None:
        for variant in CLEANUP_VARIANTS:
            with (
                self.subTest(variant=variant),
                tempfile.TemporaryDirectory(dir=self.work) as temporary,
            ):
                root = Path(temporary)
                base = root / "base"
                base.mkdir(mode=0o700)
                foreign = root / "foreign"
                (foreign / "private").mkdir(parents=True, mode=0o700)
                sentinel = foreign / "private/events.jsonl"
                sentinel.write_bytes(b"foreign sentinel")
                identity = sentinel.stat().st_ino
                observed = self.probe(variant, base, foreign, root)
                self.assertEqual(
                    observed,
                    {
                        "initialized": 1,
                        "cleaned": int(variant == "normal-cleanup-positive"),
                        "descriptor_delta": 0,
                    },
                )
                self.assertEqual(sentinel.read_bytes(), b"foreign sentinel")
                self.assertEqual(sentinel.stat().st_ino, identity)
                if variant == "normal-cleanup-positive":
                    self.assertEqual(list(base.iterdir()), [])
                else:
                    self.assertEqual(list((base / "held-run").iterdir()), [])


if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":

    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests

        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
