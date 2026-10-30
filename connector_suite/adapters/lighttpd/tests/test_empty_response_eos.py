"""Compile the actual patched entity bridge and zero-length header completion.

The pinned upstream CL0 branch is the baseline when no matching patch hunk
exists. This preserves the original failing behavior instead of reproducing a
desired implementation in the test. This is a core-bridge regression, not a
claim that a hosted module lifecycle ran.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


CONNECTOR = source_path('connectors/lighttpd')
PATCH = CONNECTOR / "patches/0001-lighttpd-msconnector-stream-hooks.patch"
UPSTREAM_EMPTY_BRANCH = """if (0 == r->resp_body_scratchpad)
                    r->resp_body_finished = 1;"""


def target_fragment(patch, filename):
    section = patch.split("+++ b/" + filename + "\n", 1)[1].split("\n--- a/", 1)[0]
    return "\n".join(line[1:] for line in section.splitlines()
        if line.startswith(("+", " ")) and not line.startswith("+++"))


def function(fragment, name):
    matched = re.search(r"(?:static )?int\s+" + re.escape(name) + r"\s*\(", fragment)
    if matched is None:
        raise ValueError("Actual core bridge function missing: " + name)
    start = fragment.index("{", matched.start())
    depth = 1
    end = start + 1
    while depth:
        depth += (fragment[end] == "{") - (fragment[end] == "}")
        end += 1
    return fragment[matched.start():end]


def empty_branch(patch):
    fragment = target_fragment(patch, "src/http-header-glue.c")
    needle = "if (0 == r->resp_body_scratchpad)"
    if needle not in fragment:
        return UPSTREAM_EMPTY_BRANCH
    start = fragment.index(needle)
    following = fragment[start + len(needle):].lstrip()
    if not following.startswith("{"):
        return fragment[start:fragment.index(";", start) + 1]
    opening = fragment.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (fragment[end] == "{") - (fragment[end] == "}")
        end += 1
    return fragment[start:end]


class EmptyResponseEosTest(unittest.TestCase):
    def test_zero_length_exactly_once_failure_and_incomplete_body(self):
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "The native core regression requires the configured C compiler")
        patch = PATCH.read_text()
        chunk = target_fragment(patch, "src/http_chunk.c")
        bridge = function(chunk, "http_chunk_msconnector_entity_body")
        close = function(chunk, "http_chunk_msconnector_entity_close")
        branch = empty_branch(patch)
        source = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
typedef int plugin_body_hook_result;
enum { HTTP_VERSION_1_1 = 11, PLUGIN_BODY_HOOK_CONTINUE = 0,
       HANDLER_GO_ON = 0, HANDLER_ERROR = -1 };
typedef struct {
    int http_version, resp_body_entity_hook_eos_sent;
    int resp_body_entity_hook_suppressed, resp_body_finished;
    off_t resp_body_entity_hook_next_offset, resp_body_scratchpad;
} request_st;
static int eos_calls, append_calls, callback_result;
static plugin_body_hook_result plugins_call_handle_response_body(
        request_st *r, const unsigned char *data, size_t length, off_t offset, int eos) {
    (void)r; (void)data; (void)offset;
    eos_calls += eos != 0;
    append_calls += length != 0;
    return callback_result;
}
BRIDGE
CLOSE
static int complete_headers(request_st *r) {
    BRANCH
    return HANDLER_GO_ON;
}
int main(void) {
    request_st zero = {.http_version = HTTP_VERSION_1_1, .resp_body_scratchpad = 0};
    if (complete_headers(&zero) != HANDLER_GO_ON) return 10;
    if (eos_calls != 1 || append_calls != 0 || !zero.resp_body_entity_hook_eos_sent) {
        fprintf(stderr, "CL0 expected EOS1/append0/accepted1; got %d/%d/%d\n",
            eos_calls, append_calls, zero.resp_body_entity_hook_eos_sent);
        return 11;
    }
    if (complete_headers(&zero) != HANDLER_GO_ON || eos_calls != 1) return 12;
    request_st incomplete = {.http_version = HTTP_VERSION_1_1, .resp_body_scratchpad = 5};
    if (complete_headers(&incomplete) != HANDLER_GO_ON || eos_calls != 1
            || incomplete.resp_body_entity_hook_eos_sent || incomplete.resp_body_finished) return 13;
    request_st failed = {.http_version = HTTP_VERSION_1_1, .resp_body_scratchpad = 0};
    callback_result = -1;
    if (complete_headers(&failed) != HANDLER_ERROR || eos_calls != 2
            || failed.resp_body_entity_hook_eos_sent || append_calls != 0) return 14;
    return 0;
}
""".replace("BRIDGE", bridge).replace("CLOSE", close).replace("BRANCH", branch)
        temporary_root = Path(os.environ.get("TMP_ROOT") or os.environ.get("RUNNER_TEMP")
            or "/var/tmp/codex/ModSecurity-conector/tmp")
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="lighttpd-cl0-eos-", dir=temporary_root) as temporary:
            root = Path(temporary)
            program = root / "regression.c"
            program.write_text(source)
            built = subprocess.run([compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
                str(program), "-o", str(root / "regression")], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            executed = subprocess.run([str(root / "regression")], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
