from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from urllib.parse import urlparse


ROOT = connector_root()
GENERATOR_PATH = source_path('scripts/generate_compiler_guides.py', root=ROOT)
GUIDE_DIRECTORY = source_path('docs/build/compilers', root=ROOT)
SLUGS = ("apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd")
MODSECURITY_REF_COMMAND = "MODSECURITY_REF=\"v3.0.17\""
MODSECURITY_COMMIT_COMMAND = "MODSECURITY_COMMIT=\"1925753989ccce977cdaae417b55c9726c7cf02c\""
COMMON_BEGINNER_COMMANDS = (
    MODSECURITY_REF_COMMAND,
    MODSECURITY_COMMIT_COMMAND,
    'git clone --branch "$MODSECURITY_REF" --single-branch https://github.com/owasp-modsecurity/ModSecurity.git ModSecurity',
    "cd ModSecurity",
    "git fetch --tags origin",
    'git verify-tag "$MODSECURITY_REF"',
    'git checkout --detach "$MODSECURITY_REF"',
    'test "$(git rev-parse HEAD)" = "$MODSECURITY_COMMIT"',
    "git submodule update --init --recursive",
    "git submodule status",
    "./build.sh",
    "./configure",
    "make",
    "make check",
    "sudo make install",
)

ENGLISH_HEADINGS = [
    "1. Purpose and selected integration path",
    "2. Build components",
    "3. Official upstream documentation",
    "4. Prerequisites",
    "5. Prepare libmodsecurity v3",
    "6. Provide the host or proxy",
    "7. Build and integrate the connector",
    "8. Configuration",
    "9. Build and ABI validation",
    "10. Local HTTP/1.1 functional test",
    "11. Package-assisted path",
    "12. Repository-controlled test path",
    "13. Update and rebuild",
    "14. Uninstall and cleanup",
    "15. Troubleshooting",
    "16. Variables and placeholders",
    "17. Boundaries and non-claims",
]

GERMAN_HEADINGS = [
    "1. Zweck und ausgewählter Integrationspfad",
    "2. Komponenten des Builds",
    "3. Offizielle Upstream-Dokumentation",
    "4. Voraussetzungen",
    "5. ModSecurity vorbereiten",
    "6. Host oder Proxy bereitstellen",
    "7. Connector bauen und einbinden",
    "8. Konfiguration",
    "9. Build- und ABI-Validierung",
    "10. Lokaler HTTP/1.1-Funktionstest",
    "11. Paketgestützter Weg",
    "12. Repository-gesteuerter Testweg",
    "13. Aktualisieren und neu bauen",
    "14. Deinstallation und Cleanup",
    "15. Troubleshooting",
    "16. Variablen und Platzhalter",
    "17. Grenzen und nicht erhobene Claims",
]


def load_generator() -> object:
    module = load_source(GENERATOR_PATH)
    return module


GENERATOR = load_generator()


def guide(slug: str, german: bool = False) -> str:
    suffix = ".de" if german else ""
    return (GUIDE_DIRECTORY / f"{slug}{suffix}.md").read_text(encoding="utf-8")


def common_guide(german: bool = False) -> str:
    suffix = ".de" if german else ""
    return (GUIDE_DIRECTORY / f"libmodsecurity{suffix}.md").read_text(encoding="utf-8")


def headings(content: str) -> list[str]:
    return re.findall(r"^## (.+)$", content, flags=re.MULTILINE)


def numbered_section(content: str, number: int) -> str:
    start = re.search(rf"^## {number}\. .+$", content, flags=re.MULTILINE)
    if start is None:
        raise AssertionError(f"missing section {number}")
    end = re.search(r"^## (?!#)", content[start.end() :], flags=re.MULTILINE)
    return content[start.start() : start.end() + (end.start() if end else len(content))]


def h2_section(content: str, heading: str) -> str:
    start = re.search(rf"^## {re.escape(heading)}$", content, flags=re.MULTILINE)
    if start is None:
        raise AssertionError(f"missing heading: {heading}")
    end = re.search(r"^## (?!#)", content[start.end() :], flags=re.MULTILINE)
    return content[start.start() : start.end() + (end.start() if end else len(content))]


def h3_section(content: str, heading: str) -> str:
    start = re.search(rf"^### {re.escape(heading)}$", content, flags=re.MULTILINE)
    if start is None:
        raise AssertionError(f"missing heading: {heading}")
    end = re.search(r"^(?:## |### )(?!#)", content[start.end() :], flags=re.MULTILINE)
    return content[start.start() : start.end() + (end.start() if end else len(content))]


def shell_blocks(content: str) -> list[str]:
    return re.findall(r"```sh\n(.*?)\n```", content, flags=re.DOTALL)


def nonempty_shell_lines(content: str) -> list[str]:
    return [line for line in content.splitlines() if line.strip()]


def variable_names(content: str) -> set[str]:
    variables = numbered_section(content, 16)
    return set(re.findall(r"^\| ([A-Za-z_][A-Za-z0-9_]*) \|", variables, flags=re.MULTILINE))


def shell_variables(content: str) -> set[str]:
    return set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", "\n".join(shell_blocks(content))))


def executable_shell_lines(content: str) -> list[str]:
    lines: list[str] = []
    for block in shell_blocks(content):
        delimiter: str | None = None
        for line in block.splitlines():
            if delimiter is not None:
                if line == delimiter:
                    delimiter = None
                continue
            lines.append(line)
            match = re.search(r"<<['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", line)
            if match is not None:
                delimiter = match.group(1)
    return lines


def shell_assignments(content: str) -> list[str]:
    return re.findall(
        r"(?<![A-Za-z0-9_-])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=",
        "\n".join(executable_shell_lines(content)),
    )


def leading_shell_assignments(content: str) -> list[str]:
    return re.findall(
        r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=",
        "\n".join(executable_shell_lines(content)),
        flags=re.MULTILINE,
    )


def local_markdown_targets(document: Path) -> set[Path]:
    targets: set[Path] = set()
    for target in re.findall(r"\]\(([^)]+)\)", document.read_text(encoding="utf-8")):
        target = target.split("#", maxsplit=1)[0]
        if not target or "://" in target or target.startswith("mailto:"):
            continue
        targets.add((document.parent / target).resolve())
    return targets


def target_exists(target: str) -> bool:
    makefile = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
    if re.search(rf"^{re.escape(target)}(?:[\s:]|$)", makefile, flags=re.MULTILINE):
        return True
    return any(
        target in line.split()[1:]
        for line in makefile.splitlines()
        if line.startswith(".PHONY:")
    )


def expected_headings(slug: str, german: bool) -> list[str]:
    headings_for_language = list(GERMAN_HEADINGS if german else ENGLISH_HEADINGS)
    headings_for_language.insert(
        2,
        "Connector in diesem Repository"
        if german
        else "Connector in this repository",
    )
    if slug in {"apache", "nginx"}:
        headings_for_language.insert(
            4,
            "Alternative: offizieller Upstream-Connector"
            if german
            else "Alternative: official upstream connector",
        )
    return headings_for_language


def connector_link_target(path: str) -> Path:
    return (GUIDE_DIRECTORY / path).resolve()


def is_allowed_official_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        return False
    origin_and_path = f"{parsed.netloc}{parsed.path}".rstrip("/")
    return any(
        origin_and_path == allowed or origin_and_path.startswith(f"{allowed}/")
        for allowed in GENERATOR.OFFICIAL_DOMAINS
    )


class CompilerGuideGenerationTest(unittest.TestCase):
    maxDiff = None

    def test_lighttpd_contract_accepts_generated_series_provenance(self) -> None:
        self.assertEqual(
            GENERATOR.LIGHTTPD_CONTRACT["LIGHTTPD_SERIES"],
            ".".join(GENERATOR.LIGHTTPD_VERSION.split(".")[:2]),
        )

    def test_generator_model_contains_one_shared_engine_contract(self) -> None:
        common = GENERATOR.COMMON_MODSECURITY
        for key in (
            "common_modsecurity_beginner_commands",
            "common_modsecurity_command_explanations",
            "common_modsecurity_advanced",
            "connector_engine_reference",
        ):
            self.assertIn(key, common)
        self.assertEqual(COMMON_BEGINNER_COMMANDS, tuple(common["common_modsecurity_beginner_commands"]))
        explanations = tuple(common["common_modsecurity_command_explanations"])
        self.assertEqual(len(COMMON_BEGINNER_COMMANDS), len(explanations))
        self.assertTrue(all(len(explanation) == 2 for explanation in explanations))
        self.assertEqual(set(SLUGS), set(common["connector_engine_reference"]))
        self.assertEqual(set(SLUGS), set(GENERATOR.HOST_SETUP))
        required_host_fields = {
            "host_simple_intro",
            "host_simple_variables",
            "host_download_steps",
            "host_build_steps",
            "host_success_check",
            "host_advanced_verification",
            "host_source_alternative",
        }
        for slug, setup in GENERATOR.HOST_SETUP.items():
            self.assertTrue(required_host_fields.issubset(setup), slug)
            self.assertLessEqual(len(setup["host_simple_variables"]), 3, slug)
        for slug, info in GENERATOR.MANUAL_GUIDES.items():
            self.assertNotIn("host_intro", info)
            self.assertNotIn("host_commands", info)
            self.assertTrue(
                {
                    "repository_connector_title",
                    "repository_connector_path",
                    "repository_connector_readme",
                    "repository_connector_source_links",
                    "repository_connector_build_files",
                    "repository_connector_build_steps",
                    "alternative_connector_title",
                    "alternative_connector_url",
                    "alternative_connector_note",
                }.issubset(info),
            )
            self.assertEqual(len(info["repository_connector_title"]), 2)
            self.assertEqual(info["repository_connector_path"], f"connectors/{slug}")
            self.assertEqual(len(info["repository_connector_readme"]), 2)
            self.assertEqual(len(info["repository_connector_build_steps"]), 2)
            self.assertEqual(len(info["alternative_connector_note"]), 2)
        self.assertEqual(set(SLUGS), set(GENERATOR.ACTIVE_MANUAL_VARIABLES))
        for slug, names in GENERATOR.ACTIVE_MANUAL_VARIABLES.items():
            available = {name for name, _, _ in GENERATOR.MANUAL_GUIDES[slug]["variables"]}
            self.assertTrue(names.issubset(available), slug)

    def test_generated_files_are_complete_current_and_idempotent(self) -> None:
        rendered = GENERATOR.rendered_files()
        expected = {
            "README.md",
            "README.de.md",
            "overview.md",
            "overview.de.md",
            "libmodsecurity.md",
            "libmodsecurity.de.md",
            *{f"{slug}{suffix}.md" for slug in SLUGS for suffix in ("", ".de")},
        }
        self.assertEqual(expected, set(rendered))
        self.assertEqual(expected, {path.name for path in GUIDE_DIRECTORY.glob("*.md")})
        for name, content in rendered.items():
            self.assertEqual(content.rstrip() + "\n", (GUIDE_DIRECTORY / name).read_text(encoding="utf-8"), name)

        with tempfile.TemporaryDirectory(prefix="compiler-guides-") as temporary:
            original_output = GENERATOR.OUTPUT
            GENERATOR.OUTPUT = Path(temporary)
            try:
                GENERATOR.main()
                first = {path.name: path.read_text(encoding="utf-8") for path in GENERATOR.OUTPUT.glob("*.md")}
                GENERATOR.main()
                second = {path.name: path.read_text(encoding="utf-8") for path in GENERATOR.OUTPUT.glob("*.md")}
            finally:
                GENERATOR.OUTPUT = original_output
        self.assertEqual(first, second)

    def test_selected_metadata_literals_have_single_guide_owners(self) -> None:
        self.assertEqual(
            GENERATOR.PACKAGE_STATUS_ASSISTED_SOURCE_BUILD,
            "package-assisted source build",
        )
        self.assertEqual(
            GENERATOR.PACKAGE_STATUS_PROFILE_UNAVAILABLE,
            "selected profile not available package-only",
        )
        self.assertEqual(GENERATOR.HOST_SOURCE_PATCHED, "patched source")
        self.assertEqual(GENERATOR.SOURCE_MAPPING_HEADING, "Source mapping")
        self.assertEqual(
            {
                str(info["package_status"])
                for info in GENERATOR.DETAILS.values()
            },
            {
                GENERATOR.PACKAGE_STATUS_ASSISTED_SOURCE_BUILD,
                GENERATOR.PACKAGE_STATUS_PROFILE_UNAVAILABLE,
            },
        )
        self.assertTrue(
            {
                str(info["package_status"])
                for info in GENERATOR.DETAILS.values()
            }.issubset(GENERATOR.PACKAGE_STATUSES)
        )
        self.assertEqual(
            GENERATOR.DETAILS["lighttpd"]["host_source"],
            GENERATOR.HOST_SOURCE_PATCHED,
        )
        self.assertEqual(
            sum(
                english == GENERATOR.SOURCE_MAPPING_HEADING
                for info in GENERATOR.MANUAL_GUIDES.values()
                for english, _, _ in info["repository_connector_build_files"]
            ),
            6,
        )

    def test_common_beginner_block_is_exact_and_bilingual(self) -> None:
        english = common_guide()
        german = common_guide(german=True)
        english_beginner = h2_section(english, "Simple official build")
        german_beginner = h2_section(german, "Einfacher offizieller Build")
        english_meanings = h2_section(english, "Meaning of the commands")
        german_meanings = h2_section(german, "Bedeutung der Befehle")
        english_blocks = shell_blocks(english_beginner)
        german_blocks = shell_blocks(german_beginner)
        self.assertEqual(len(english_blocks), 1)
        self.assertEqual(len(german_blocks), 1)
        self.assertEqual(list(COMMON_BEGINNER_COMMANDS), nonempty_shell_lines(english_blocks[0]))
        self.assertEqual(english_blocks, german_blocks)

        for beginner in (english_beginner, german_beginner):
            self.assertNotRegex(beginner, r"(?m)^export\b")
            self.assertNotIn("PKG_CONFIG_PATH", beginner)
            self.assertNotIn("LD_LIBRARY_PATH", beginner)
            self.assertNotIn("pkg-config", beginner)
            self.assertNotRegex(beginner, r"(?m)^ldd\b")

        for command in COMMON_BEGINNER_COMMANDS:
            self.assertIn(f"| `{command}` |", english_meanings)
            self.assertIn(f"| `{command}` |", german_meanings)
        self.assertLess(english.index("## Simple official build"), english.index("## Meaning of the commands"))
        self.assertLess(german.index("## Einfacher offizieller Build"), german.index("## Bedeutung der Befehle"))

    def test_common_beginner_build_verifies_the_pinned_release_before_building(self) -> None:
        required_commands = (
            MODSECURITY_REF_COMMAND,
            MODSECURITY_COMMIT_COMMAND,
            'git verify-tag "$MODSECURITY_REF"',
            'git checkout --detach "$MODSECURITY_REF"',
            'test "$(git rev-parse HEAD)" = "$MODSECURITY_COMMIT"',
            "git submodule update --init --recursive",
            "git submodule status",
            "make check",
        )
        for content, heading in (
            (common_guide(), "Simple official build"),
            (common_guide(german=True), "Einfacher offizieller Build"),
        ):
            beginner = h2_section(content, heading)
            self.assertNotIn("v3/master", beginner)
            for command in required_commands:
                self.assertIn(command, beginner)
            self.assertLess(beginner.index('git verify-tag "$MODSECURITY_REF"'), beginner.index('git checkout --detach "$MODSECURITY_REF"'))
            self.assertLess(beginner.index('git checkout --detach "$MODSECURITY_REF"'), beginner.index('test "$(git rev-parse HEAD)" = "$MODSECURITY_COMMIT"'))
            self.assertLess(beginner.index("make check"), beginner.index("sudo make install"))

    def test_advanced_engine_information_follows_the_simple_build(self) -> None:
        for content, beginner_heading, heading in (
            (common_guide(), "Simple official build", "Advanced and reproducible builds"),
            (common_guide(german=True), "Einfacher offizieller Build", "Fortgeschrittene und reproduzierbare Builds"),
        ):
            self.assertLess(content.index(f"## {beginner_heading}"), content.index(f"## {heading}"))
            advanced = h2_section(content, heading)
            for marker in (
                MODSECURITY_REF_COMMAND.split('"', 2)[1],
                "MODSECURITY_COMMIT",
                "verify-tag",
                "SHA",
                "MODSECURITY_PREFIX",
                "PKG_CONFIG_PATH",
                "LD_LIBRARY_PATH",
                "make check",
                "make -j",
                "CFLAGS",
                "CXXFLAGS",
                "LDFLAGS",
                "build-provenance.txt",
            ):
                self.assertIn(marker, advanced)

    def test_connector_guides_link_the_shared_engine_and_do_not_repeat_it(self) -> None:
        for slug in SLUGS:
            english = guide(slug)
            german = guide(slug, german=True)
            self.assertIn("](libmodsecurity.md)", english, slug)
            self.assertIn("](libmodsecurity.de.md)", german, slug)
            for content in (english, german):
                connector_shell = "\n".join(shell_blocks(content))
                self.assertNotIn(COMMON_BEGINNER_COMMANDS[0], connector_shell, slug)
                self.assertNotIn("\n./build.sh\n", f"\n{connector_shell}\n", slug)
                if slug == "apache":
                    self.assertIn('if [ -w "$("$APXS" -q LIBEXECDIR)" ]; then', connector_shell)
                    self.assertIn("sudo make install", connector_shell)
                else:
                    self.assertNotIn("sudo make install", connector_shell, slug)

                section_five = numbered_section(content, 5)
                self.assertIn('/usr/local/modsecurity', section_five, slug)
                self.assertIn('export MODSECURITY_INCLUDE_DIR=', section_five, slug)
                self.assertIn('export MODSECURITY_LIB_DIR=', section_five, slug)

    def test_connector_structure_and_bilingual_technical_parity(self) -> None:
        for slug in SLUGS:
            english = guide(slug)
            german = guide(slug, german=True)
            self.assertEqual(expected_headings(slug, False), headings(english), slug)
            self.assertEqual(expected_headings(slug, True), headings(german), slug)
            self.assertEqual(shell_blocks(english), shell_blocks(german), slug)
            self.assertEqual(variable_names(english), variable_names(german), slug)

    def test_host_documentation_is_separate_from_repository_connectors(self) -> None:
        required_url_fragments = {
            "apache": ("httpd.apache.org/docs/2.4/install.html", "httpd.apache.org/docs/2.4/programs/apxs.html"),
            "nginx": ("nginx.org/",),
            "haproxy": ("github.com/haproxy/haproxy", "docs.haproxy.org"),
            "envoy": ("envoyproxy.io",),
            "traefik": ("doc.traefik.io",),
            "lighttpd": ("github.com/lighttpd", "download.lighttpd.net"),
        }
        for slug in SLUGS:
            sources = [
                source
                for source in GENERATOR.MANUAL_GUIDES[slug]["official_sources"]
                if source[1] != "https://github.com/owasp-modsecurity/ModSecurity"
            ]
            self.assertGreaterEqual(len(sources), 2, slug)
            urls = []
            for title, url, english_scope, german_scope, version_scope in sources:
                self.assertTrue(title)
                self.assertTrue(english_scope)
                self.assertTrue(german_scope)
                self.assertTrue(version_scope)
                self.assertTrue(is_allowed_official_url(url), f"{slug}: {url}")
                urls.append(url)
                for content in (guide(slug), guide(slug, german=True)):
                    section = numbered_section(content, 3)
                    self.assertIn(f"]({url})", section, f"{slug}: {url}")
                    self.assertNotIn("../../../connectors/", section, slug)
            joined = "\n".join(urls)
            for fragment in required_url_fragments[slug]:
                self.assertIn(fragment, joined, slug)
            alternative_url = GENERATOR.MANUAL_GUIDES[slug]["alternative_connector_url"]
            self.assertNotIn(alternative_url, urls, slug)

    def test_every_guide_links_its_repository_connector_and_real_paths(self) -> None:
        for slug in SLUGS:
            info = GENERATOR.MANUAL_GUIDES[slug]
            english_section = h2_section(guide(slug), "Connector in this repository")
            german_section = h2_section(guide(slug, german=True), "Connector in diesem Repository")
            self.assertIn("primary connector path", english_section, slug)
            self.assertIn("primäre Connectorpfad", german_section, slug)
            self.assertIn(f"{info['repository_connector_path']}/", english_section, slug)
            self.assertIn(f"{info['repository_connector_path']}/", german_section, slug)

            expected_english = {
                info["repository_connector_readme"][0],
                *{
                    path
                    for _, _, path in info["repository_connector_source_links"]
                },
                *{
                    path
                    for _, _, path in info["repository_connector_build_files"]
                },
            }
            expected_german = {
                info["repository_connector_readme"][1],
                *{
                    path
                    for _, _, path in info["repository_connector_source_links"]
                },
                *{
                    path
                    for _, _, path in info["repository_connector_build_files"]
                },
            }
            for path in expected_english:
                self.assertIn(f"]({path})", english_section, f"{slug}: {path}")
                self.assertTrue(connector_link_target(path).exists(), f"{slug}: {path}")
            for path in expected_german:
                self.assertIn(f"]({path})", german_section, f"{slug}: {path}")
                self.assertTrue(connector_link_target(path).exists(), f"{slug}: {path}")

            normalize = lambda paths: {
                path.replace("README.de.md", "README.md") for path in paths
            }
            self.assertEqual(normalize(expected_english), normalize(expected_german), slug)

    def test_all_generated_relative_markdown_links_resolve(self) -> None:
        for document in sorted(GUIDE_DIRECTORY.glob("*.md")):
            for target in local_markdown_targets(document):
                self.assertTrue(target.exists(), f"{document.name}: {target}")

    def test_repository_sections_link_readme_source_build_and_configuration_material(self) -> None:
        required_configuration = {
            "apache": "../../../connectors/apache/harness/apache_smoke.conf",
            "nginx": "../../../connectors/nginx/config",
            "haproxy": "../../../connectors/haproxy/harness/run_haproxy_htx_runtime.sh",
            "envoy": "../../../connectors/envoy/config/",
            "traefik": "../../../connectors/traefik/config/traefik-native-middleware-static.yaml",
            "lighttpd": "../../../connectors/lighttpd/config/lighttpd-native.conf",
        }
        for slug, configuration_path in required_configuration.items():
            info = GENERATOR.MANUAL_GUIDES[slug]
            all_paths = {
                *{path for _, _, path in info["repository_connector_source_links"]},
                *{path for _, _, path in info["repository_connector_build_files"]},
            }
            self.assertIn(configuration_path, all_paths, slug)
            self.assertTrue(connector_link_target(configuration_path).exists(), slug)

    def test_apache_and_nginx_upstreams_are_prose_only_alternatives(self) -> None:
        alternatives = {
            "apache": "ModSecurity-apache",
            "nginx": "ModSecurity-nginx",
        }
        for slug, upstream_name in alternatives.items():
            for german in (False, True):
                content = guide(slug, german=german)
                heading = (
                    "Alternative: offizieller Upstream-Connector"
                    if german
                    else "Alternative: official upstream connector"
                )
                alternative = h2_section(content, heading)
                self.assertIn(
                    GENERATOR.MANUAL_GUIDES[slug]["alternative_connector_url"],
                    alternative,
                )
                self.assertIn(upstream_name, alternative)
                self.assertEqual(shell_blocks(alternative), [], slug)
                self.assertNotIn("git clone", alternative, slug)
                self.assertNotIn("./configure", alternative, slug)
                self.assertNotIn("make ", alternative, slug)
                outside_alternative = content.replace(alternative, "")
                self.assertNotIn(upstream_name, outside_alternative, slug)

    def test_variable_tables_do_not_cross_connector_boundaries(self) -> None:
        pid_names = {
            "upstream_pid",
            "haproxy_pid",
            "engine_pid",
            "traefik_pid",
            "lighttpd_pid",
        }
        expected_pids = {
            "apache": set(),
            "nginx": set(),
            "haproxy": {"upstream_pid", "haproxy_pid"},
            "envoy": set(),
            "traefik": {"upstream_pid", "engine_pid", "traefik_pid"},
            "lighttpd": {"lighttpd_pid"},
        }
        for slug in SLUGS:
            names = variable_names(guide(slug))
            self.assertEqual(expected_pids[slug], names & pid_names, slug)
        for slug in ("apache", "nginx"):
            self.assertTrue(variable_names(guide(slug)).isdisjoint(pid_names), slug)

    def test_section_six_is_small_host_only_setup(self) -> None:
        localized = (
            (
                False,
                "Simple path",
                "What was installed or built?",
                "Check the result",
                "Source build and integrity checks",
            ),
            (
                True,
                "Einfacher Weg",
                "Was wurde installiert oder gebaut?",
                "Erfolg prüfen",
                "Source-Build und Integritätsprüfung",
            ),
        )
        for slug in SLUGS:
            for german, simple_heading, installed_heading, success_heading, source_heading in localized:
                section = numbered_section(guide(slug, german=german), 6)
                for heading in (simple_heading, installed_heading, success_heading, source_heading):
                    self.assertIn(f"### {heading}", section, f"{slug}: {heading}")
                simple = h3_section(section, simple_heading)
                self.assertNotRegex(simple, r"(?m)^export\b", slug)
                self.assertLessEqual(len(leading_shell_assignments(simple)), 3, slug)
                self.assertNotIn("LD_LIBRARY_PATH", simple, slug)
                for forbidden in (
                    "SecRule",
                    "cat >",
                    "curl -i",
                    "curl --http1.1",
                    "http://127.0.0.1",
                    "full-lifecycle",
                    "evidence-check",
                    " -k start",
                    " -s quit",
                    "\nkill ",
                ):
                    self.assertNotIn(forbidden, section, f"{slug}: {forbidden}")
                self.assertRegex(section.lower(), r"sha256|gpg|checksum", slug)

                if slug in {"apache", "nginx", "haproxy", "traefik", "lighttpd"}:
                    self.assertLess(section.index("sha256sum") if "sha256sum" in section else section.index("gpg --verify"), section.index("tar -x"), slug)
                if slug in {"apache", "nginx"}:
                    self.assertLess(section.index("gpg --verify"), section.index("tar -x"), slug)
                if slug == "envoy":
                    self.assertLess(section.index("sha256sum -c -"), section.index("chmod 755 envoy"), slug)

    def test_connector_configuration_validation_and_runtime_stay_in_sections_seven_to_ten(self) -> None:
        nginx = {number: numbered_section(guide("nginx"), number) for number in range(6, 11)}
        for token in ("./configure", "make install", "nginx.conf", "curl -i"):
            self.assertNotIn(token, nginx[6])
        self.assertNotIn("git clone https://github.com/owasp-modsecurity/ModSecurity-nginx.git", nginx[6])
        self.assertNotIn("ModSecurity-nginx", nginx[6])
        for token in (
            "./configure",
            'MSCONNECTOR_COMMON_INC="$CONNECTOR_ROOT/common/include"',
            'MSCONNECTOR_COMMON_SRC="$CONNECTOR_ROOT/common/src"',
            'MSCONNECTOR_PROFILE_REGISTRY_ROOT="$CONNECTOR_ROOT"',
            'MODSECURITY_INC="$MODSECURITY_INCLUDE_DIR"',
            'MODSECURITY_LIB="$MODSECURITY_LIB_DIR"',
            "--with-compat",
            '--add-dynamic-module="$CONNECTOR_ROOT/connectors/nginx"',
            'make -j"$JOBS"',
            "make install",
        ):
            self.assertIn(token, nginx[7])
        self.assertNotIn("./auto/configure", nginx[7])
        self.assertNotIn('cp -a "objs/ngx_http_modsecurity_module.so"', nginx[7])
        self.assertNotIn("--add-module=", nginx[7])
        self.assertNotIn("ModSecurity-nginx", nginx[7])
        self.assertIn("modsecurity-local.conf", nginx[8])
        self.assertIn("nginx.conf", nginx[8])
        self.assertIn("load_module modules/ngx_http_modsecurity_module.so;", nginx[8])
        self.assertIn('root "$NGINX_DOCROOT";', nginx[8])
        self.assertIn('index index.html;', nginx[8])
        self.assertNotIn('return 200 "nginx modsecurity test', nginx[8])
        self.assertIn('"$INSTALL_DIR/sbin/nginx" -V', nginx[9])
        for token in (
            'test -f "$INSTALL_DIR/modules/ngx_http_modsecurity_module.so"',
            "--add-dynamic-module=$CONNECTOR_ROOT/connectors/nginx",
            'file "$INSTALL_DIR/modules/ngx_http_modsecurity_module.so"',
            'ldd "$INSTALL_DIR/modules/ngx_http_modsecurity_module.so" | grep -F libmodsecurity | grep -Fv "not found"',
        ):
            self.assertIn(token, nginx[9])
        self.assertNotIn("--add-module=$WORKDIR/ModSecurity-nginx", nginx[9])
        for token in ('-t -p "$INSTALL_DIR"', '= "200"', '= "403"', "-s quit"):
            self.assertIn(token, nginx[10])

        apache = {number: numbered_section(guide("apache"), number) for number in range(6, 11)}
        self.assertIn("apache2-dev", apache[6])
        self.assertIn('test -x "$INSTALL_DIR/bin/apxs"', apache[6])
        self.assertIn('APXS="$HOME/.local/apache-modsecurity/bin/apxs"', apache[7])
        for token in (
            'command -v apxs || command -v apxs2',
            'cd "$CONNECTOR_ROOT/connectors/apache"',
            'test -f "$CONNECTOR_ROOT/connectors/apache/configure.ac"',
            "materialize-connector-source.sh",
            '--adapter-dir "$CONNECTOR_ROOT/connectors/apache"',
            "./autogen.sh",
            '--with-libmodsecurity="$MODSECURITY_PREFIX"',
            '--with-apxs="$APXS"',
            '--with-apache="$HTTPD_BIN"',
            'sudo make install',
        ):
            self.assertIn(token, apache[7])
        self.assertNotIn("git clone https://github.com/owasp-modsecurity/ModSecurity-apache.git", apache[7])
        self.assertIn('"$APXS" -q LIBEXECDIR', apache[9])
        self.assertIn("LoadModule security3_module", apache[8])
        for token in ("HTTPD_RUNTIME_ROOT", "HTTPD_DOCUMENT_ROOT", "HTTPD_MODULES", "DefaultRuntimeDir", 'printf "apache modsecurity test'):
            self.assertIn(token, apache[8])
        self.assertIn('LD_LIBRARY_PATH="$MODSECURITY_LIB_DIR', apache[9])
        self.assertIn('LD_LIBRARY_PATH="$MODSECURITY_LIB_DIR', apache[10])
        self.assertIn('= "200"', apache[10])
        self.assertIn('= "403"', apache[10])

        haproxy = {number: numbered_section(guide("haproxy"), number) for number in range(6, 11)}
        self.assertNotIn("build-overlay.sh", haproxy[6])
        self.assertIn('sh "$CONNECTOR_ROOT/connectors/haproxy/htx-overlay/build-overlay.sh"', haproxy[7])
        self.assertIn('MODSECURITY_INCLUDE_DIR', numbered_section(guide("haproxy"), 5))
        self.assertIn('MODSECURITY_LIB_DIR', numbered_section(guide("haproxy"), 5))
        self.assertIn("modsecurity-htx", haproxy[8])
        self.assertIn("phase4-mode safe", haproxy[8])
        self.assertIn("SPOE/SPOP", haproxy[7])
        self.assertNotIn('"$HAPROXY_HTX_BIN" -c', haproxy[8])
        self.assertIn('"$HAPROXY_HTX_BIN" -c', haproxy[9])
        self.assertIn('grep -Fv "not found"', haproxy[9])
        self.assertIn('kill -0 "$haproxy_pid"', haproxy[10])
        self.assertIn('test "$attempt" -lt 50', haproxy[10])
        self.assertIn('= "200"', haproxy[10])
        self.assertIn('= "403"', haproxy[10])

        envoy = {number: numbered_section(guide("envoy"), number) for number in range(6, 11)}
        self.assertNotIn("build_ext_proc.sh", envoy[6])
        self.assertIn("build_ext_proc.sh", envoy[7])
        self.assertIn("ExternalProcessor", envoy[7])
        self.assertNotIn("--mode validate", envoy[8])
        self.assertIn("--mode validate", envoy[9])
        self.assertIn("--check-config", envoy[9])
        self.assertIn('EXT_PROC_CONFIG="$CONNECTOR_ROOT/connectors/envoy/config/envoy-ext-proc-service.json"', envoy[8])
        self.assertIn('--runtime-config "$EXT_PROC_RUNTIME_CONFIG"', envoy[9])
        self.assertIn('EXT_PROC_RUNTIME_CONFIG="$EXT_PROC_RUNTIME_CONFIG"', envoy[10])

        traefik = {number: numbered_section(guide("traefik"), number) for number in range(6, 11)}
        self.assertNotIn("make test-unit", h3_section(traefik[6], "Simple path"))
        self.assertNotIn("git clone", h3_section(traefik[6], "Simple path"))
        for token in ("build-native-middleware.sh", "build-engine-service.sh", "Go middleware", "engine service"):
            self.assertIn(token, traefik[7])
        for token in ("engineMode: uds", "engineSocketPath", "localPlugins"):
            self.assertIn(token, traefik[8])
        self.assertNotIn('"$TRAEFIK_BIN" check', traefik[8])
        self.assertIn('"$TRAEFIK_BIN" check', traefik[9])
        self.assertIn("--check-config", traefik[9])
        self.assertIn('traefik-native-runtime-$(date -u +%Y%m%dT%H%M%SZ)', traefik[8])
        self.assertIn('mktemp -d /tmp/msconnector-traefik-uds.XXXXXX', traefik[8])
        self.assertIn('chmod 700 "$TRAEFIK_SOCKET_DIR"', traefik[8])
        self.assertIn('TRAEFIK_ENGINE_SOCKET="$TRAEFIK_SOCKET_DIR/engine.sock"', traefik[8])
        self.assertIn('test "${#TRAEFIK_ENGINE_SOCKET}" -lt 108', traefik[8])
        self.assertIn('native_middleware/.' , traefik[8])
        self.assertIn('( cd "$TRAEFIK_RUNTIME_ROOT" && "$TRAEFIK_BIN" check --configFile="$TRAEFIK_STATIC_CONFIG" )', traefik[9])
        self.assertNotRegex(traefik[9], r'(?m)^"\$TRAEFIK_BIN" check --configFile=')
        self.assertIn('test -S "$TRAEFIK_ENGINE_SOCKET"', traefik[10])
        self.assertIn('stat -c "%a" "$TRAEFIK_ENGINE_SOCKET"', traefik[10])
        self.assertIn('kill -0 "$traefik_pid"', traefik[10])
        self.assertIn('test "$attempt" -lt 50', traefik[10])
        self.assertIn('= "200"', traefik[10])
        self.assertIn('= "403"', traefik[10])

        lighttpd = {number: numbered_section(guide("lighttpd"), number) for number in range(6, 11)}
        self.assertIn("patch --dry-run -p1", lighttpd[6])
        self.assertIn("patch -p1", lighttpd[6])
        self.assertNotIn("build_module.sh", lighttpd[6])
        self.assertIn("build_module.sh", lighttpd[7])
        self.assertNotIn(" -tt -f", lighttpd[8])
        self.assertIn(" -tt -f", lighttpd[9])
        self.assertIn("Entity-Body", guide("lighttpd"))
        self.assertIn('LIGHTTPD_DOCUMENT_ROOT', lighttpd[8])
        self.assertIn('index.html', lighttpd[8])
        self.assertIn('server.modules = ( "mod_indexfile", "mod_msconnector", "mod_staticfile" )', lighttpd[8])
        self.assertIn('index-file.names = ( "index.html" )', lighttpd[8])
        self.assertIn('grep -Fv "not found"', lighttpd[9])
        self.assertIn('mod_(indexfile|staticfile)_plugin_init$', lighttpd[9])
        self.assertIn('kill -0 "$lighttpd_pid"', lighttpd[10])
        self.assertIn('test "$attempt" -lt 50', lighttpd[10])
        self.assertIn('= "200"', lighttpd[10])
        self.assertIn('= "403"', lighttpd[10])

        for slug, sections in (("haproxy", haproxy), ("envoy", envoy), ("traefik", traefik), ("lighttpd", lighttpd)):
            self.assertNotRegex(sections[7], r"\bsh connectors/", slug)

        traefik_source = h3_section(traefik[6], "Source build and integrity checks")
        self.assertIn('grep -E "^go " go.mod', traefik_source)
        self.assertIn('grep -Fx "go 1.25.0" go.mod', traefik_source)
        self.assertIn("git rev-parse HEAD", traefik_source)
        for slug, module in (("envoy", "envoy/ext_proc"), ("traefik", "traefik/native_middleware")):
            minimum = re.search(r"(?m)^go (\S+)$", (source_path('connectors', root=ROOT) / module / "go.mod").read_text()).group(1)
            self.assertIn(f'go {minimum}', numbered_section(guide(slug), 4))

    def test_repository_test_paths_follow_manual_steps_and_targets_exist(self) -> None:
        for connector in GENERATOR.CONNECTORS:
            slug = connector["slug"]
            repository = numbered_section(guide(slug), 12)
            self.assertIn('mkdir -p "$VERIFIED_RUN_PARENT"', repository)
            self.assertIn('cd "$VERIFIED_RUN_PARENT"', repository)
            self.assertIn("automate and test the build and integration steps described above", repository)
            for target in (
                "check-framework",
                "prepare-runtime-components",
                connector["build"],
                connector["config"],
                connector["start"],
                connector["runtime"],
                connector["full"],
                f"evidence-check-{slug}",
            ):
                self.assertIn(f"make {target}", repository, f"{slug}: {target}")
                self.assertTrue(target_exists(target), f"missing Make target: {target}")

    def test_manual_shell_placeholders_are_documented(self) -> None:
        ignored = {"HOME", "PWD", "archive", "attempt", "module", "mpm", "CN", "subjectAltName"}
        for slug in SLUGS:
            for german in (False, True):
                content = guide(slug, german=german)
                manual = "".join(numbered_section(content, number) for number in range(4, 11))
                used_names = shell_variables(manual) | set(shell_assignments(manual))
                unexplained = used_names - variable_names(content) - ignored
                self.assertEqual(set(), unexplained, f"{slug} german={german}")

                outside_variable_table = content.replace(numbered_section(content, 16), "")
                documented_but_unused = variable_names(content) - (
                    shell_variables(outside_variable_table)
                    | set(shell_assignments(outside_variable_table))
                )
                self.assertEqual(set(), documented_but_unused, f"{slug} german={german}")

    def test_every_generated_shell_block_is_syntactically_valid(self) -> None:
        documents = [*sorted(GUIDE_DIRECTORY.glob("*.md"))]
        for document in documents:
            for index, block in enumerate(shell_blocks(document.read_text(encoding="utf-8")), start=1):
                result = subprocess.run(
                    ["sh", "-n"], input=block, text=True, capture_output=True, check=False
                )
                self.assertEqual(result.returncode, 0, f"{document.name} block {index}: {result.stderr}")

    def test_prefix_and_cleanup_regressions_are_explicit(self) -> None:
        for content in (common_guide(), common_guide(german=True)):
            self.assertIn("/usr/local/modsecurity/include/modsecurity", content)
            self.assertIn("/usr/local/modsecurity", content)
            self.assertNotIn("/usr/local/include/modsecurity", content)
        for slug in SLUGS:
            content = guide(slug)
            self.assertIn('MODSECURITY_PREFIX="${MODSECURITY_PREFIX:-/usr/local/modsecurity}"', content)
            cleanup = numbered_section(content, 14)
            self.assertNotIn("src/modsecurity-connectors", cleanup)
            self.assertIn("$HOME/", cleanup)
        self.assertIn('test ! -e "$LIGHTTPD_PATCHED_SRC"', guide("lighttpd"))
        for german in (False, True):
            lighttpd = guide("lighttpd", german=german)
            self.assertIn("test -x ./configure", lighttpd)
            self.assertIn("autogen.log", lighttpd)
            self.assertNotIn("test -x ./autogen.sh && ./autogen.sh", lighttpd)
        self.assertIn('htx-overlay-$(date -u +%Y%m%dT%H%M%SZ)', guide("haproxy"))

    def test_guides_use_safe_defaults_and_state_required_boundaries(self) -> None:
        forbidden_claims = (
            "production-ready",
            "production hardened",
            "security verified",
            "crs verified",
            "full matrix verified",
        )
        prohibited_absolute_source = re.compile(r"(?:^|[=:\"'\s])/src(?:/|[\"'\s])")
        broad_library_copy = re.compile(r"\b(?:cp|install)\b[^\n]*?/usr/lib(?:/|\b)")
        german_boundary = "Diese Anleitung beschreibt einen nachvollziehbaren Entwicklungs- und Integrationsbuild. Sie ist keine Produktionsfreigabe."
        for content in (
            common_guide(),
            common_guide(german=True),
            *[guide(slug) for slug in SLUGS],
            *[guide(slug, german=True) for slug in SLUGS],
        ):
            self.assertIn(GENERATOR.MARKER, content)
            self.assertNotIn("/root", content)
            self.assertNotIn("/var/tmp", content)
            for block in shell_blocks(content):
                self.assertNotRegex(block, prohibited_absolute_source)
                self.assertNotRegex(block, broad_library_copy)
            for claim in forbidden_claims:
                self.assertNotIn(claim, content.lower())
        for slug in SLUGS:
            self.assertIn(german_boundary, guide(slug, german=True), slug)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
