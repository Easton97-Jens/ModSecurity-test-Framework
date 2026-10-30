#!/usr/bin/env python3
"""Check bilingual documentation invariants for repository-owned docs."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root

import argparse
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote


LINK_RE = re.compile(r"(?<!!)\[[^\]\n]+\]\(([^)\n]+)\)")
REFERENCE_LINK_RE = re.compile(r"^\s*\[[^\]]+\]:\s+(\S+)")
URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
MARKDOWN_SUFFIX = ".md"
GERMAN_MARKDOWN_SUFFIX = ".de.md"
TOOLS_MRTS = "tools/MRTS"
GERMAN_GENERATED_NOTE = "Diese deutsche Datei ist eine übersetzte Begleitdatei"
SPECIAL_LANGUAGE_INDEXES: tuple[tuple[Path, Path], ...] = ()
CHANGE_RECORDS_DIRECTORY = Path("reports/audits/change-records")
PR_TEMPLATE_PATH = Path(".github/pull_request_template.md")
LOCAL_CODEX_ROOT_FILENAMES = frozenset(
    {
        "AGENTS.md",
        "AGENTS.override.md",
    }
)
LOCAL_CODEX_ROOT_DIRECTORY_NAMES = frozenset({".codex"})
FORBIDDEN_LOCAL_LANGUAGE_COMPANIONS = frozenset(
    {"AGENTS.de.md", "AGENTS.override.de.md"}
)
PR_TEMPLATE_REQUIRED_HEADINGS = {
    "English": (
        "### Summary",
        "### Change Record",
        "### Motivation and context",
        "### Acceptance criteria",
        "### Detailed changes",
        "### Tests and command results",
        "### Runtime evidence",
        "### Security impact",
        "### Documentation status",
        "### Known limitations",
        "### Checks not run",
    ),
    "Deutsch": (
        "### Zusammenfassung",
        "### Change Record",
        "### Motivation und Kontext",
        "### Akzeptanzkriterien",
        "### Detaillierte Änderungen",
        "### Tests und Befehlsergebnisse",
        "### Runtime-Evidence",
        "### Sicherheitsauswirkung",
        "### Dokumentationsstatus",
        "### Bekannte Einschränkungen",
        "### Nicht ausgeführte Prüfungen",
    ),
}
CHANGE_RECORD_REQUIRED_HEADINGS = {
    "English": (
        "## Identity",
        "## Motivation and problem statement",
        "## Acceptance criteria",
        "## Implementation decision and rationale",
        "## Changed files",
        "## Commands executed",
        "## Security impact",
        "## Runtime evidence",
        "## Known limitations",
        "## Remaining risks",
        "## Checks not run and rationale",
        "## Final diff and review status",
    ),
    "Deutsch": (
        "## Identität",
        "## Motivation und Problemstellung",
        "## Akzeptanzkriterien",
        "## Implementierungsentscheidung und Begründung",
        "## Geänderte Dateien",
        "## Ausgeführte Befehle",
        "## Security-Auswirkung",
        "## Runtime-Evidence",
        "## Bekannte Einschränkungen",
        "## Verbleibende Risiken",
        "## Nicht ausgeführte Prüfungen mit Begründung",
        "## Finaler Diff- und Review-Status",
    ),
}
CHANGE_RECORD_IDENTITY_LABELS = (
    ("Change ID", "Change-ID"),
    ("Date (UTC)", "Datum (UTC)"),
    ("Base revision", "Basis-Revision"),
)
COMMON_DESIGN_NOTE_PATHS = {
    "English": Path("common/docs/design.md"),
    "Deutsch": Path("common/docs/design.de.md"),
}
COMMON_DESIGN_NOTE_STATUS = {
    "English": "Status: current-boundary reference",
    "Deutsch": "Status: aktuelle Grenzreferenz",
}
COMMON_DESIGN_NOTE_REQUIRED_CONTENT = {
    "English": (
        "[Repository concept](../../docs/repository-concept.md)",
        "[Architecture](../../docs/architecture.md)",
        "[Testing and evidence](../../docs/testing-and-evidence.md)",
        "`common/` is connector-neutral",
        "must not include or depend on host SDK types",
        "bounded views or copies",
        "`connectors/<name>/`",
        "`modules/ModSecurity-test-Framework/`",
    ),
    "Deutsch": (
        "[Repository-Konzept](../../docs/repository-concept.de.md)",
        "[Architektur](../../docs/architecture.de.md)",
        "[Tests und Nachweise](../../docs/testing-and-evidence.de.md)",
        "`common/` bleibt host-neutral",
        "keine Host-SDK-Typen",
        "begrenzte Ansichten oder Kopien",
        "`connectors/<name>/`",
        "`modules/ModSecurity-test-Framework/`",
    ),
}
COMMON_DESIGN_SELECTED_ROUTES = {
    "Apache": "native-httpd-module",
    "NGINX": "native-nginx-http-module",
    "HAProxy": "native-htx-filter",
    "Envoy": "ext_proc",
    "Traefik": "native-traefik-middleware",
    "lighttpd": "patched-native-lighttpd",
}
COMMON_DESIGN_ROUTE_ROW_RE = re.compile(
    r"^\|([^|]+)\|\s*`([^`]+)`\s*\|",
    re.MULTILINE,
)
COMMON_DESIGN_HISTORICAL_TOKENS = (
    "sidecar_proxy",
    "http-ext-authz-service",
    "http-forwardauth-service",
    "spoe-spop-agent",
    "ext_authz",
    "forwardauth",
)
COMMON_DESIGN_HISTORICAL_MARKERS = (
    "historical",
    "historisch",
    "compatibility_only",
    "kompatibilität",
)
HEADING_RE = re.compile(r"^(#{1,6})\s+\S", re.MULTILINE)
TABLE_ROW_RE = re.compile(r"^\|.*\|\s*$")
ROOT_AGENT_INCLUDE_RE = re.compile(
    r"^\s*@([A-Za-z0-9][A-Za-z0-9._-]*\.md)\s*$",
    re.MULTILINE,
)


def is_tools_mrts(path: Path) -> bool:
    text = path.as_posix()
    return text.startswith(("tools/MRTS/", "modules/ModSecurity-test-Framework/tools/MRTS/"))


def agent_referenced_root_markdown(repo: Path) -> frozenset[Path]:
    """Return root Markdown control files explicitly included by local AGENTS files."""
    paths: set[Path] = set()
    for filename in LOCAL_CODEX_ROOT_FILENAMES:
        source = repo / filename
        if not source.is_file():
            continue
        for match in ROOT_AGENT_INCLUDE_RE.finditer(
            source.read_text(encoding="utf-8", errors="replace")
        ):
            paths.add(Path(match.group(1)))
    return frozenset(paths)


def is_local_codex_path(
    path: Path,
    agent_referenced_paths: frozenset[Path] = frozenset(),
) -> bool:
    """Return true for developer-local Codex configuration only."""
    return (
        (len(path.parts) == 1 and path.name in LOCAL_CODEX_ROOT_FILENAMES)
        or (bool(path.parts) and path.parts[0] in LOCAL_CODEX_ROOT_DIRECTORY_NAMES)
        or path in agent_referenced_paths
    )


def is_ignored(path: Path) -> bool:
    return (
        any(part in {".git", ".venv", "__pycache__"} for part in path.parts)
        or path.name == "actions-update-report.md"
        or is_tools_mrts(path)
    )


def git_ignored_paths(repo: Path) -> frozenset[Path]:
    """Return local, ignored paths that are not repository-owned documentation."""
    result = subprocess.run(
        ["git", "ls-files", "--others", "--ignored", "--exclude-standard", "-z"],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if result.returncode != 0:
        return frozenset()
    return frozenset(Path(path) for path in result.stdout.split("\0") if path)


def is_git_ignored(path: Path, ignored_paths: frozenset[Path]) -> bool:
    return any(path == ignored or ignored in path.parents for ignored in ignored_paths)


def german_counterpart(path: Path) -> Path:
    return path.with_name(path.name.removesuffix(MARKDOWN_SUFFIX) + GERMAN_MARKDOWN_SUFFIX)


def english_counterpart(path: Path) -> Path:
    return path.with_name(path.name.removesuffix(GERMAN_MARKDOWN_SUFFIX) + MARKDOWN_SUFFIX)


def is_special_language_index(path: Path) -> bool:
    return any(path in pair for pair in SPECIAL_LANGUAGE_INDEXES)


def needs_structural_parity(path: Path) -> bool:
    """Return true for policy-owned documentation with stable prose structure."""
    text = path.as_posix()
    return (
        len(path.parts) == 1
        or text.startswith("common/")
        or text.startswith("connectors/")
        or text.startswith("docs/")
        or text.startswith("ci/")
        or text.startswith("config/")
        or text.startswith("tests/")
        or text.startswith("licenses/")
        or text.startswith(f"{CHANGE_RECORDS_DIRECTORY.as_posix()}/")
    )


def pair_required(path: Path) -> bool:
    text = path.as_posix()
    name = path.name
    if name.endswith(GERMAN_MARKDOWN_SUFFIX) or is_tools_mrts(path) or is_special_language_index(path):
        return False
    if path == PR_TEMPLATE_PATH:
        return False
    if needs_structural_parity(path):
        return True
    if name.startswith("COMPILE_") and name.endswith(".md"):
        return True
    if text.startswith("examples/"):
        return True
    if text.startswith("reports/"):
        return True
    if text.startswith(".github/") and name.endswith(".md"):
        return True
    if text in {
        "modules/ModSecurity-test-Framework/README.md",
        "modules/ModSecurity-test-Framework/TEST-COVERAGE-SUMMARY.md",
        "modules/ModSecurity-test-Framework/ci/README.md",
    }:
        return True
    if text.startswith("modules/ModSecurity-test-Framework/docs/"):
        return True
    if text.startswith("connectors/") and (
        "/reports/" in text
        or "/docs/evidence" in text
        or text.endswith("/docs/coverage-decision-matrix.md")
        or text.endswith("/docs/spoe-external-evidence.md")
    ):
        return True
    return False


def english_sources(repo: Path) -> list[Path]:
    ignored_paths = git_ignored_paths(repo)
    agent_referenced_paths = agent_referenced_root_markdown(repo)
    return sorted(
        path
        for path in repo.rglob("*.md")
        if not is_ignored(path)
        and not is_git_ignored(path.relative_to(repo), ignored_paths)
        and not is_local_codex_path(
            path.relative_to(repo),
            agent_referenced_paths,
        )
        and pair_required(path.relative_to(repo))
    )


def checked_markdown_files(repo: Path) -> list[Path]:
    files: set[Path] = set()
    for source in english_sources(repo):
        files.add(source)
        companion = german_counterpart(source)
        if companion.exists():
            files.add(companion)
    pr_template = repo / PR_TEMPLATE_PATH
    if pr_template.exists():
        files.add(pr_template)
    for english_index, german_index in SPECIAL_LANGUAGE_INDEXES:
        if (repo / english_index).exists():
            files.add(repo / english_index)
        if (repo / german_index).exists():
            files.add(repo / german_index)
    return sorted(files)


def markdown_fence_marker(line: str) -> str | None:
    """Return a Markdown fence marker, including its delimiter and length."""

    stripped = line.lstrip()
    if not stripped or stripped[0] not in {"`", "~"}:
        return None
    marker = stripped[0]
    length = 0
    while length < len(stripped) and stripped[length] == marker:
        length += 1
    if length < 3:
        return None
    return marker * length


def closes_markdown_fence(line: str, opener: str) -> bool:
    """Require the opener delimiter and at least its length for a close fence."""

    marker = markdown_fence_marker(line)
    if marker is None or marker[0] != opener[0] or len(marker) < len(opener):
        return False
    return not line.lstrip()[len(marker) :].strip()


def heading_levels(text: str) -> list[int]:
    levels: list[int] = []
    opener: str | None = None
    for line in text.splitlines():
        if opener is not None:
            if closes_markdown_fence(line, opener):
                opener = None
            continue
        marker = markdown_fence_marker(line)
        if marker is not None:
            opener = marker
            continue
        match = HEADING_RE.match(line)
        if match:
            levels.append(len(match.group(1)))
    return levels


def table_block_rows(text: str) -> list[int]:
    blocks: list[int] = []
    current = 0
    opener: str | None = None
    for line in text.splitlines():
        if opener is not None:
            if closes_markdown_fence(line, opener):
                opener = None
            continue
        marker = markdown_fence_marker(line)
        if marker is not None:
            opener = marker
            continue
        if TABLE_ROW_RE.match(line):
            current += 1
        elif current:
            blocks.append(current)
            current = 0
    if current:
        blocks.append(current)
    return blocks


def fenced_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    opener: str | None = None
    for line in text.splitlines():
        if opener is not None:
            current.append(line)
            if closes_markdown_fence(line, opener):
                blocks.append("\n".join(current))
                current = []
                opener = None
            continue
        marker = markdown_fence_marker(line)
        if marker is not None:
            current = [line]
            opener = marker
    if opener is not None:
        blocks.append("\n".join(current))
    return blocks


def markdown_table_value(text: str, label: str) -> str | None:
    pattern = re.compile(rf"^\|\s*{re.escape(label)}\s*\|\s*(.*?)\s*\|\s*$", re.MULTILINE)
    match = pattern.search(text)
    return match.group(1) if match else None


def check_change_record_headings(
    source: Path,
    companion: Path,
    source_text: str,
    companion_text: str,
) -> list[str]:
    errors: list[str] = []
    for heading in CHANGE_RECORD_REQUIRED_HEADINGS["English"]:
        if heading not in source_text:
            errors.append(f"{source}: missing Change Record section {heading!r}")
    for heading in CHANGE_RECORD_REQUIRED_HEADINGS["Deutsch"]:
        if heading not in companion_text:
            errors.append(f"{companion}: missing Change Record section {heading!r}")
    return errors


def check_change_record_filename_and_identity(
    source: Path,
    companion: Path,
    source_text: str,
    companion_text: str,
) -> list[str]:
    errors: list[str] = []
    record_name = source.name.removesuffix(".md")
    if "-" not in record_name:
        errors.append(
            f"{source}: Change Record filename must use <change-id>-<name>.md"
        )
    for english_label, german_label in CHANGE_RECORD_IDENTITY_LABELS:
        english_value = markdown_table_value(source_text, english_label)
        german_value = markdown_table_value(companion_text, german_label)
        if english_value is None:
            errors.append(f"{source}: missing Change Record identity field {english_label!r}")
        if german_value is None:
            errors.append(f"{companion}: missing Change Record identity field {german_label!r}")
        if english_value is not None and german_value is not None and english_value != german_value:
            errors.append(
                f"{source}: Change Record identity field {english_label!r} differs from "
                f"{companion} ({english_value!r} != {german_value!r})"
            )
    return errors


def check_change_record_pair(
    source: Path,
    companion: Path,
    source_text: str,
    companion_text: str,
) -> list[str]:
    if source.parent != CHANGE_RECORDS_DIRECTORY or source.name == "README.md":
        return []

    errors = check_change_record_headings(source, companion, source_text, companion_text)

    if source.name == "TEMPLATE.md":
        return errors

    errors.extend(
        check_change_record_filename_and_identity(
            source,
            companion,
            source_text,
            companion_text,
        )
    )
    return errors


def check_pr_template(repo: Path) -> list[str]:
    path = repo / PR_TEMPLATE_PATH
    if not path.exists():
        return []

    text = path.read_text(encoding="utf-8", errors="replace")
    errors: list[str] = []
    for language, headings in PR_TEMPLATE_REQUIRED_HEADINGS.items():
        section_heading = f"## {language}"
        if section_heading not in text:
            errors.append(
                f"{PR_TEMPLATE_PATH}: missing bilingual "
                f"{language} section"
            )
        for heading in headings:
            if heading not in text:
                errors.append(
                    f"{PR_TEMPLATE_PATH}: missing "
                    f"{language} required section {heading!r}"
                )
    return errors


def check_forbidden_local_language_companions(repo: Path) -> list[str]:
    return [
        f"{filename}: local Codex configuration must not have a German companion"
        for filename in sorted(FORBIDDEN_LOCAL_LANGUAGE_COMPANIONS)
        if (repo / filename).exists()
    ]


def ordinary_pair_errors(repo: Path, source: Path) -> list[str]:
    errors: list[str] = []
    rel_source = source.relative_to(repo)
    companion = german_counterpart(source)
    if not companion.exists():
        return [f"{rel_source}: missing German companion {companion.relative_to(repo)}"]
    rel_companion = companion.relative_to(repo)
    english_switch = f"**Language:** English | [Deutsch]({companion.name})"
    german_switch = f"**Sprache:** [English]({source.name}) | Deutsch"
    source_text = source.read_text(encoding="utf-8", errors="replace")
    companion_text = companion.read_text(encoding="utf-8", errors="replace")
    if english_switch not in source_text:
        errors.append(f"{rel_source}: missing language switch {english_switch!r}")
    if german_switch not in companion_text:
        errors.append(f"{rel_companion}: missing language switch {german_switch!r}")
    errors.extend(structural_pair_errors(rel_source, rel_companion, source_text, companion_text))
    errors.extend(check_change_record_pair(rel_source, rel_companion, source_text, companion_text))
    return errors


def structural_pair_errors(
    source: Path, companion: Path, source_text: str, companion_text: str,
) -> list[str]:
    if not needs_structural_parity(source):
        return []
    errors: list[str] = []
    english_headings = heading_levels(source_text)
    german_headings = heading_levels(companion_text)
    if english_headings != german_headings:
        errors.append(f"{source}: heading-level structure differs from {companion} ({english_headings!r} != {german_headings!r})")
    if english_headings.count(1) != 1 or german_headings.count(1) != 1:
        errors.append(f"{source}: each language companion must contain exactly one H1")
    english_tables = table_block_rows(source_text)
    german_tables = table_block_rows(companion_text)
    if english_tables != german_tables:
        errors.append(f"{source}: table-row structure differs from {companion} ({english_tables!r} != {german_tables!r})")
    if fenced_blocks(source_text) != fenced_blocks(companion_text):
        errors.append(f"{source}: fenced code-block content differs from {companion}")
    return errors


def special_language_index_errors(repo: Path) -> list[str]:
    errors: list[str] = []
    for english_index, german_index in SPECIAL_LANGUAGE_INDEXES:
        english_path = repo / english_index
        german_path = repo / german_index
        if not english_path.exists() or not german_path.exists():
            errors.append(f"language index pair is incomplete: {english_index} / {german_index}")
            continue
        english_text = english_path.read_text(encoding="utf-8", errors="replace")
        german_text = german_path.read_text(encoding="utf-8", errors="replace")
        expected_english = f"**Language:** English | [Deutsch](../de/{german_index.name})"
        expected_german = f"**Sprache:** [English](../en/{english_index.name}) | Deutsch"
        if expected_english not in english_text:
            errors.append(f"{english_index}: missing language-index switch {expected_english!r}")
        if expected_german not in german_text:
            errors.append(f"{german_index}: missing language-index switch {expected_german!r}")
    return errors


def check_pairs_and_switches(repo: Path) -> list[str]:
    errors = special_language_index_errors(repo)
    for source in english_sources(repo):
        errors.extend(ordinary_pair_errors(repo, source))
    return errors


def common_design_note_errors(language: str, relative_path: Path, text: str) -> list[str]:
    errors: list[str] = []
    normalized_text = " ".join(text.split())
    if COMMON_DESIGN_NOTE_STATUS[language] not in text:
        errors.append(f"{relative_path}: missing current Common design-note status {COMMON_DESIGN_NOTE_STATUS[language]!r}")
    for required in COMMON_DESIGN_NOTE_REQUIRED_CONTENT[language]:
        if required not in normalized_text:
            errors.append(f"{relative_path}: missing required Common design-note content {required!r}")
    prohibited_status = "scaffolded" if language == "English" else "eingerüstet"
    if prohibited_status in text.casefold():
        errors.append(f"{relative_path}: obsolete scaffolded status is not a current architecture claim")
    errors.extend(common_design_route_errors(relative_path, text))
    errors.extend(common_design_historical_errors(relative_path, text))
    return errors


def common_design_route_errors(relative_path: Path, text: str) -> list[str]:
    errors: list[str] = []
    route_rows = [(connector.strip(), route) for connector, route in COMMON_DESIGN_ROUTE_ROW_RE.findall(text)]
    routes = dict(route_rows)
    if len(routes) != len(route_rows):
        errors.append(f"{relative_path}: selected-route rows must not repeat a connector")
    for connector, expected_route in COMMON_DESIGN_SELECTED_ROUTES.items():
        route = routes.get(connector)
        if route != expected_route:
            errors.append(f"{relative_path}: selected route for {connector} must be {expected_route!r}, found {route!r}")
    for connector in sorted(set(routes) - set(COMMON_DESIGN_SELECTED_ROUTES)):
        errors.append(f"{relative_path}: unexpected selected-route row for {connector}")
    return errors


def common_design_historical_errors(relative_path: Path, text: str) -> list[str]:
    errors: list[str] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        normalized = line.casefold()
        if any(token in normalized for token in COMMON_DESIGN_HISTORICAL_TOKENS) and not any(marker in normalized for marker in COMMON_DESIGN_HISTORICAL_MARKERS):
            errors.append(f"{relative_path}:{line_number}: historical integration mode must be explicitly marked historical or compatibility_only")
    return errors


def check_common_design_note_contract(repo: Path) -> list[str]:
    """Keep the Common design note aligned with the binding selected routes."""
    errors: list[str] = []
    for language, relative_path in COMMON_DESIGN_NOTE_PATHS.items():
        path = repo / relative_path
        if not path.is_file():
            errors.append(f"{relative_path}: missing Common design note")
            continue
        errors.extend(common_design_note_errors(language, relative_path, path.read_text(encoding="utf-8", errors="replace")))
    return errors


def normalized_targets(line: str) -> list[str]:
    targets = [match.group(1).strip() for match in LINK_RE.finditer(line)]
    reference = REFERENCE_LINK_RE.match(line)
    if reference:
        targets.append(reference.group(1).strip())
    return targets


def normalize_local_target(raw_target: str) -> str:
    target = raw_target.strip().strip("<>")
    if " " in target and not target.startswith("#"):
        target = target.split()[0]
    if not target or target.startswith("#") or URI_SCHEME_RE.match(target):
        return ""
    return unquote(target.split("#", 1)[0].split("?", 1)[0])


def local_link_errors(
    repo: Path, path: Path, agent_referenced_paths: frozenset[Path],
) -> list[str]:
    errors: list[str] = []
    rel_path = path.relative_to(repo)
    opener: str | None = None
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if opener is not None:
            opener = None if closes_markdown_fence(line, opener) else opener
            continue
        marker = markdown_fence_marker(line)
        if marker is not None:
            opener = marker
            continue
        for raw_target in normalized_targets(line):
            errors.extend(local_target_errors(repo, path, rel_path, line_number, line, raw_target, agent_referenced_paths))
    return errors


def local_target_errors(
    repo: Path,
    path: Path,
    rel_path: Path,
    line_number: int,
    line: str,
    raw_target: str,
    agent_referenced_paths: frozenset[Path],
) -> list[str]:
    target = normalize_local_target(raw_target)
    if not target:
        return []
    candidate = (path.parent / target).resolve()
    try:
        rel_candidate = candidate.relative_to(repo)
    except ValueError:
        return [f"{rel_path}:{line_number}: link escapes repository: {raw_target}"]
    if is_local_codex_path(rel_candidate, agent_referenced_paths):
        return []
    if not candidate.exists():
        return [f"{rel_path}:{line_number}: missing local link target: {raw_target}"]
    if not german_link_prefers_companion(path, target, line, candidate):
        return []
    return [f"{rel_path}:{line_number}: German link should prefer {german_counterpart(candidate).relative_to(repo)} instead of {raw_target}"]


def german_link_prefers_companion(path: Path, target: str, line: str, candidate: Path) -> bool:
    if not path.name.endswith(GERMAN_MARKDOWN_SUFFIX):
        return False
    if not target.endswith(MARKDOWN_SUFFIX) or target.endswith(GERMAN_MARKDOWN_SUFFIX):
        return False
    return "**Sprache:**" not in line and german_counterpart(candidate).exists()


def check_links(repo: Path) -> list[str]:
    agent_referenced_paths = agent_referenced_root_markdown(repo)
    return [
        error
        for path in checked_markdown_files(repo)
        for error in local_link_errors(repo, path, agent_referenced_paths)
    ]


def check_generated_german_notes(repo: Path) -> list[str]:
    errors: list[str] = []
    for source in english_sources(repo):
        if not source.name.endswith(".generated.md") and source.name != "actions-update-report.md":
            continue
        companion = german_counterpart(source)
        if not companion.exists():
            continue
        text = companion.read_text(encoding="utf-8", errors="replace")
        if GERMAN_GENERATED_NOTE not in text:
            errors.append(f"{companion.relative_to(repo)}: missing manual generated-companion note")
    return errors


def git_status(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        return result.stderr.strip() or result.stdout.strip()
    return result.stdout.strip()


def check_tools_mrts_clean(repo: Path) -> list[str]:
    errors: list[str] = []
    root_status = git_status(repo, "status", "--short", "--", TOOLS_MRTS, "modules/ModSecurity-test-Framework/tools/MRTS")
    if root_status:
        errors.append(f"tools/MRTS paths changed in parent repository:\n{root_status}")
    framework_root = repo / "modules/ModSecurity-test-Framework"
    if (framework_root / ".git").exists() or (framework_root / TOOLS_MRTS).exists():
        framework_status = git_status(framework_root, "status", "--short", "--", TOOLS_MRTS)
        if framework_status:
            errors.append(f"tools/MRTS paths changed in framework module:\n{framework_status}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=connector_root())
    args = parser.parse_args(argv)
    repo = args.repo_root.resolve()

    errors: list[str] = []
    errors.extend(check_pairs_and_switches(repo))
    errors.extend(check_common_design_note_contract(repo))
    errors.extend(check_pr_template(repo))
    errors.extend(check_forbidden_local_language_companions(repo))
    errors.extend(check_generated_german_notes(repo))
    errors.extend(check_links(repo))
    errors.extend(check_tools_mrts_clean(repo))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("bilingual docs ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
