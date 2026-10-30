#!/usr/bin/env python3
"""Static contract checks for staging the shared HAProxy HTX MRC1 client."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = connector_root()
OVERLAY = source_path('connectors/haproxy/htx-overlay', root=ROOT)
PATCH_CONTEXT_CHECKER = OVERLAY / "verify-makefile-patch-context.py"


def haproxy_makefile_anchor() -> str:
    lines = ["# preceding line\n"] * 998
    lines.extend(
        (
            "        src/hpack-huff.o src/hpack-enc.o src/ebtree.o src/hash.o\t\\\n",
            "        src/version.o src/ncbmbuf.o\n",
            "\n",
            "ifneq ($(TRACE),)\n",
            "  OBJS += src/calltrace.o\n",
            "endif\n",
        )
    )
    return "".join(lines)


class HaproxyMrc1OverlayBuildContractTests(unittest.TestCase):
    def test_build_stages_common_client_and_only_its_object(self) -> None:
        script = (OVERLAY / "build-overlay.sh").read_text(encoding="utf-8")
        patch = (OVERLAY / "haproxy-makefile.patch").read_text(encoding="utf-8")

        for source in (
            "common/runtime/response_companion_client.c",
            "common/runtime/response_companion_client.h",
            "common/runtime/response_companion_transport.h",
            "common/runtime/msconnector_runtime.h",
        ):
            self.assertIn(f'"$CONNECTOR_ROOT/{source}"', script)

        self.assertIn("src/msconnector_response_companion_client.o", patch)
        self.assertNotIn("src/msconnector_response_companion_transport.o", patch)

    def test_overlay_does_not_define_a_second_mrc1_framer(self) -> None:
        script = (OVERLAY / "build-overlay.sh").read_text(encoding="utf-8")
        filter_source = (OVERLAY / "haproxy_modsecurity_htx_filter.c").read_text(
            encoding="utf-8"
        )

        self.assertIn("response_companion_client.c", script)
        self.assertNotIn("MRC1_MAGIC", filter_source)
        self.assertNotIn("enum mrc1_opcode", filter_source)

    def test_client_header_dependencies_are_staged_under_overlay_src(self) -> None:
        script = (OVERLAY / "build-overlay.sh").read_text(encoding="utf-8")

        self.assertIn('"$WORKTREE/src/response_companion_client.h"', script)
        self.assertIn('"$WORKTREE/src/response_companion_transport.h"', script)
        self.assertIn('"$WORKTREE/src/msconnector_runtime.h"', script)

    def test_overlay_stages_and_links_the_connector_profile_registry(self) -> None:
        script = (OVERLAY / "build-overlay.sh").read_text(encoding="utf-8")
        patch = (OVERLAY / "haproxy-makefile.patch").read_text(encoding="utf-8")

        self.assertIn('connectors/profile_registry.c', script)
        self.assertIn('connectors/profile_registry.h', script)
        self.assertIn('"$WORKTREE/src/msconnector_profile_registry.c"', script)
        self.assertIn('"$WORKTREE/src/connectors/profile_registry.h"', script)
        self.assertIn('-I$WORKTREE/src/connectors', script)
        self.assertIn('src/msconnector_profile_registry.o', patch)

    def test_makefile_patch_applies_without_offset_or_fuzz(self) -> None:
        patch = OVERLAY / "haproxy-makefile.patch"
        with tempfile.TemporaryDirectory() as directory:
            makefile = Path(directory) / "Makefile"
            makefile.write_text(haproxy_makefile_anchor(), encoding="utf-8")
            context = subprocess.run(
                ["python3", str(PATCH_CONTEXT_CHECKER), "--makefile", str(makefile)],
                check=False,
                capture_output=True,
                text=True,
            )
            result = subprocess.run(
                [
                    "patch",
                    "--dry-run",
                    "--fuzz=0",
                    "--posix",
                    "-p1",
                    "-i",
                    str(patch),
                ],
                cwd=directory,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(context.returncode, 0, context.stdout + context.stderr)
        self.assertEqual(
            result.returncode,
            0,
            result.stdout + result.stderr,
        )

    def test_context_checker_rejects_a_shifted_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            makefile = Path(directory) / "Makefile"
            makefile.write_text(
                "# shift that would otherwise permit patch offset\n"
                + haproxy_makefile_anchor(),
                encoding="utf-8",
            )
            result = subprocess.run(
                ["python3", str(PATCH_CONTEXT_CHECKER), "--makefile", str(makefile)],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing offset or fuzzy", result.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
