"""On-demand controls exercise the real repository architecture CLI."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CLI = (
    ROOT
    / "connector_suite/modsecurity_connector_ci/checks/common/check-repository-architecture.py"
)
MODEL = ROOT / "connector_suite/config/testing/repository-architecture.json"


class RepositoryArchitectureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.product, self.framework = self.root / "product", self.root / "framework"
        self.write(
            self.product,
            "common/include/msconnector/neutral.h",
            "typedef int neutral;\n",
        )
        self.write(
            self.product,
            "common/src/neutral.c",
            '#include "msconnector/neutral.h"\n#include <stdint.h>\n',
        )
        self.write(
            self.product,
            "connectors/example/src/main.c",
            "int main(void) { return 0; }\n",
        )
        for owner, names in (
            (self.product, ("architecture", "test-ownership-migration")),
            (self.framework, ("architecture",)),
        ):
            for name in names:
                self.write(owner, f"docs/{name}.md", "Versioned ownership contract.\n")
        self.model = self.framework / "model.json"
        self.model.write_bytes(MODEL.read_bytes())
        subprocess.run(["git", "init", "-q", str(self.framework)], check=True)

    def write(self, root, relative, text):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def run_cli(self, expected, marker):
        completed = subprocess.run(
            [
                sys.executable,
                str(CLI),
                "--connector-root",
                str(self.product),
                "--framework-root",
                str(self.framework),
                "--model",
                str(self.model),
            ],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(
            completed.returncode, expected, completed.stdout + completed.stderr
        )
        self.assertIn(marker, completed.stdout + completed.stderr)

    def test_valid_neutral_and_test_delegation_and_bound_reader(self):
        self.write(
            self.product,
            "Makefile",
            "test:\n\t$(MAKE) -C modules/ModSecurity-test-Framework test\n",
        )
        self.write(self.product, "ci/test.py", "import modsecurity_test_framework\n")
        self.write(
            self.framework,
            "reader.py",
            "from pathlib import Path\nPath('/explicit/product/common/src/neutral.c').read_text()\n",
        )
        self.write(
            self.product,
            "connectors/example/Makefile",
            "FRAMEWORK_ROOT = modules/ModSecurity-test-Framework\nACTIVE_TEST_RUNNER = $(PYTHON) -P -m modsecurity_test_framework.connector\ntest:\n\t$(MAKE) -C $(FRAMEWORK_ROOT) test\ncheck-config:\n\t$(ACTIVE_TEST_RUNNER) --check\nruntime-smoke:\n\tsh $(FRAMEWORK_ROOT)/connector_suite/adapters/example/harness/run_smoke.sh\n",
        )
        self.run_cli(0, "PASS")

    def test_external_engine_sdk_is_neutral(self):
        self.write(
            self.product,
            "common/src/neutral.c",
            '#include "modsecurity/modsecurity.h"\n',
        )
        self.run_cli(0, "PASS")

    def test_nginx_and_apache_sdk_headers(self):
        for header in (
            "nginx.h",
            "apache2/util_filter.h",
            "nginx/ngx_config.h",
            "http_log.h",
        ):
            with self.subTest(header=header):
                self.write(
                    self.product, "common/src/neutral.c", f"#include <{header}>\n"
                )
                self.run_cli(1, "common-host-neutral")

    def test_continued_host_sdk_include(self):
        self.write(self.product, "common/src/neutral.c", "# include \\\n<nginx.h>\n")
        self.run_cli(1, "common-host-neutral")

    def test_nonliteral_common_include(self):
        self.write(
            self.product,
            "common/src/neutral.c",
            "#define HEADER <nginx.h>\n#include HEADER\n",
        )
        self.run_cli(2, "unresolved nonliteral Common include")

    def test_product_make_link_dependency_and_variable_edge(self):
        for name in (
            "Makefile",
            "makefile",
            "GNUmakefile",
            "Makefile.am",
            "product.mk",
        ):
            with self.subTest(name=name):
                self.write(
                    self.product,
                    f"connectors/example/{name}",
                    "FRAMEWORK_ROOT = modules/ModSecurity-test-Framework\nLIBDIR = $(FRAMEWORK_ROOT)/lib\nLDADD = $(LIBDIR)/test.a\n",
                )
                self.run_cli(1, "product-without-test-infrastructure")
                (self.product / f"connectors/example/{name}").unlink()

    def test_product_make_compile_recipe(self):
        self.write(
            self.product,
            "connectors/example/Makefile",
            "FRAMEWORK_ROOT = modules/ModSecurity-test-Framework\nbuild:\n\t$(CC) $(FRAMEWORK_ROOT)/fixture.c -o product\n",
        )
        self.run_cli(1, "product-without-test-infrastructure")

    def test_make_include_and_prerequisite_dependencies(self):
        for content in (
            "include ../../modules/ModSecurity-test-Framework/runtime.mk\n",
            "product: ../../modules/ModSecurity-test-Framework/runtime.a\n",
        ):
            with self.subTest(content=content):
                self.write(self.product, "connectors/example/Makefile", content)
                self.run_cli(1, "product-without-test-infrastructure")

    def test_make_comment_and_mixed_recipe_do_not_exempt_product_edges(self):
        for content in (
            "build:\n\t$(MAKE) -C modules/ModSecurity-test-Framework build-runtime # test\n",
            "ACTIVE_TEST_RUNNER = $(PYTHON) -P -m modsecurity_test_framework.connector\nbuild:\n\t$(ACTIVE_TEST_RUNNER); $(CC) modules/ModSecurity-test-Framework/fixture.c -o product\n",
            "test:\n\t$(CC) modules/ModSecurity-test-Framework/fixture.c -o product\n",
        ):
            with self.subTest(content=content):
                self.write(self.product, "connectors/example/Makefile", content)
                self.run_cli(1, "product-without-test-infrastructure")

    def test_harmless_python_c_and_go_mentions(self):
        self.write(
            self.product,
            "connectors/example/log.py",
            'print("ModSecurity-test-Framework is a separate repository")\n',
        )
        self.write(
            self.product,
            "connectors/example/src/log.c",
            'const char *message = "ModSecurity-test-Framework is a separate repository";\n',
        )
        self.write(
            self.product,
            "connectors/example/log.go",
            'package main\nconst message = "ModSecurity-test-Framework is a separate repository"\n',
        )
        self.run_cli(0, "PASS")

    def test_harmless_shell_and_build_messages(self):
        self.write(
            self.product,
            "connectors/example/log.sh",
            'echo "ModSecurity-test-Framework is separate"\nprintf "%s\\n" "ModSecurity-test-Framework is separate"\n',
        )
        self.write(
            self.product,
            "connectors/example/CMakeLists.txt",
            'message("ModSecurity-test-Framework is separate")\n',
        )
        self.write(
            self.product,
            "connectors/example/notice.m4",
            "AC_MSG_NOTICE([ModSecurity-test-Framework is separate])\n",
        )
        self.run_cli(0, "PASS")

    def test_recipe_environment_is_not_global_make_assignment(self):
        self.write(
            self.product,
            "connectors/example/Makefile",
            "FRAMEWORK_ROOT = modules/ModSecurity-test-Framework\nBUILD_ROOT = external-output\nsmoke:\n\tBUILD_ROOT=$(BUILD_ROOT) sh $(FRAMEWORK_ROOT)/connector_suite/adapters/example/harness/run_smoke.sh\nbuild:\n\t$(CC) -o $(BUILD_ROOT)/product main.c\n",
        )
        self.run_cli(0, "PASS")

    def test_python_literal_import_aliases_and_keyword(self):
        for content in (
            "from importlib import import_module\nimport_module('modsecurity_test_framework')\n",
            "import importlib as il\nil.import_module('modsecurity_test_framework')\n",
            "import importlib\nimportlib.import_module(name='modsecurity_test_framework')\n",
        ):
            with self.subTest(content=content):
                self.write(self.product, "connectors/example/loader.py", content)
                self.run_cli(1, "product-without-test-infrastructure")

    def test_go_raw_imports(self):
        for content in (
            "package main\nimport `example/ModSecurity-test-Framework/runtime`\n",
            "package main\nimport (\n _ `example/ModSecurity-test-Framework/runtime`\n)\n",
        ):
            with self.subTest(content=content):
                self.write(self.product, "connectors/example/loader.go", content)
                self.run_cli(1, "product-without-test-infrastructure")

    def test_data_extension_does_not_exempt_make_compile_or_link_sink(self):
        for command in (
            "$(CC) -x c $(SCRIPT)",
            "$(LD) -T $(SCRIPT)",
            "$(AR) r product.a $(SCRIPT)",
        ):
            with self.subTest(command=command):
                self.write(
                    self.product,
                    "connectors/example/Makefile",
                    f"SCRIPT = modules/ModSecurity-test-Framework/runtime.txt\nbuild:\n\t{command}\n",
                )
                self.run_cli(1, "product-without-test-infrastructure")

    def test_shell_template_and_autotools_build_dependencies(self):
        for name, content in (
            (
                "wrapper.in",
                "#!/bin/sh\npython modules/ModSecurity-test-Framework/runtime.py\n",
            ),
            (
                "module.m4",
                'PRODUCT_SOURCES="modules/ModSecurity-test-Framework/runtime.c"\n',
            ),
        ):
            with self.subTest(name=name):
                self.write(self.product, f"connectors/example/{name}", content)
                self.run_cli(1, "product-without-test-infrastructure")
                (self.product / f"connectors/example/{name}").unlink()

    def test_product_configure_and_nginx_build_dependency(self):
        for name in ("config", "configure.ac"):
            with self.subTest(name=name):
                self.write(
                    self.product,
                    f"connectors/example/{name}",
                    "ngx_module_srcs=modules/ModSecurity-test-Framework/fixture.c\n",
                )
                self.run_cli(1, "product-without-test-infrastructure")
                (self.product / f"connectors/example/{name}").unlink()

    def test_spaced_host_sdk_include(self):
        self.write(
            self.product,
            "common/include/msconnector/neutral.h",
            "# include <ngx_http.h>\n",
        )
        self.run_cli(1, "common-host-neutral")

    def test_nested_host_sdk_include(self):
        self.write(
            self.product,
            "common/include/msconnector/neutral.h",
            '#include "nested.h"\n',
        )
        self.write(
            self.product,
            "common/include/msconnector/nested.h",
            "#include <envoy/server/filter_config.h>\n",
        )
        self.run_cli(1, "common-host-neutral")

    def test_product_python_framework_dependency(self):
        self.write(
            self.product,
            "connectors/example/main.py",
            "import modsecurity_test_framework\n",
        )
        self.run_cli(1, "product-without-test-infrastructure")

    def test_product_dynamic_literal_framework_dependency(self):
        self.write(
            self.product,
            "connectors/example/main.py",
            "__import__('modsecurity_connector_ci')\n",
        )
        self.run_cli(1, "product-without-test-infrastructure")

    def test_product_c_framework_dependency(self):
        self.write(
            self.product,
            "connectors/example/src/main.c",
            '#include "modules/ModSecurity-test-Framework/test.h"\n',
        )
        self.run_cli(1, "product-without-test-infrastructure")

    def test_product_go_framework_dependency(self):
        self.write(
            self.product,
            "connectors/example/main.go",
            'package main\nimport "example/ModSecurity-test-Framework/runtime"\n',
        )
        self.run_cli(1, "product-without-test-infrastructure")

    def test_product_launcher_framework_dependency(self):
        self.write(
            self.product,
            "connectors/example/start.sh",
            "python modules/ModSecurity-test-Framework/run.py\n",
        )
        self.run_cli(1, "product-without-test-infrastructure")

    def test_reverse_parent_gitlink(self):
        self.write(
            self.framework,
            ".gitmodules",
            '[submodule "parent"]\n path = parent\n url = https://example.invalid/ModSecurity-conector.git\n',
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.framework),
                "update-index",
                "--add",
                "--cacheinfo",
                "160000," + "a" * 40 + ",parent",
            ],
            check=True,
        )
        self.run_cli(1, "no-parent-gitlink")

    def test_reverse_parent_local_path_and_file_url(self):
        for url in (str(self.product), self.product.as_uri()):
            with self.subTest(url=url):
                self.write(
                    self.framework,
                    ".gitmodules",
                    f'[submodule "parent"]\n path = parent\n url = {url}\n',
                )
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(self.framework),
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        "160000," + "a" * 40 + ",parent",
                    ],
                    check=True,
                )
                self.run_cli(1, "no-parent-gitlink")

    def test_reverse_parent_alternate_worktree_identity(self):
        subprocess.run(["git", "init", "-q", str(self.product)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.product),
                "-c",
                "user.name=Architecture Fixture",
                "-c",
                "user.email=architecture-fixture@example.invalid",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "architecture fixture",
            ],
            check=True,
        )
        alternate = self.root / "alternate-product"
        subprocess.run(
            [
                "git",
                "-C",
                str(self.product),
                "worktree",
                "add",
                "-q",
                "--detach",
                str(alternate),
            ],
            check=True,
        )
        self.write(
            self.framework,
            ".gitmodules",
            f'[submodule "parent"]\n path = parent\n url = {alternate}\n',
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.framework),
                "update-index",
                "--add",
                "--cacheinfo",
                "160000," + "a" * 40 + ",parent",
            ],
            check=True,
        )
        self.run_cli(1, "no-parent-gitlink")

    def test_framework_subdirectory_is_not_repository_root(self):
        self.framework = self.framework / "nested"
        self.write(
            self.framework,
            "docs/architecture.md",
            "Subdirectory is not the repository root.\n",
        )
        self.run_cli(2, "actual Git top-level")

    def test_undeclared_gitlink(self):
        self.write(self.framework, ".gitmodules", "")
        subprocess.run(
            [
                "git",
                "-C",
                str(self.framework),
                "update-index",
                "--add",
                "--cacheinfo",
                "160000," + "a" * 40 + ",unknown",
            ],
            check=True,
        )
        self.run_cli(2, "gitlink without")

    def test_missing_model(self):
        self.model.unlink()
        self.run_cli(2, "ERROR")

    def test_invalid_empty_and_weakened_model(self):
        for text in ("", "{}", "{", "null", '{"schema_version": 1}'):
            with self.subTest(text=text):
                self.model.write_text(text)
                self.run_cli(2, "ERROR")

    def test_model_duplicate_key(self):
        self.model.write_text('{"schema_version": 1, "schema_version": 1}')
        self.run_cli(2, "duplicate model key")

    def test_empty_required_source_scope(self):
        (self.product / "connectors/example/src/main.c").unlink()
        self.run_cli(2, "empty required source scope")

    def test_unresolved_common_dependency(self):
        self.write(
            self.product, "common/src/neutral.c", '#include "msconnector/absent.h"\n'
        )
        self.run_cli(2, "unresolved Common local dependency")

    def test_unresolved_angle_local_dependency(self):
        self.write(
            self.product, "common/src/neutral.c", "#include <msconnector/absent.h>\n"
        )
        self.run_cli(2, "unresolved Common local dependency")


if __name__ == "__main__":
    unittest.main()
