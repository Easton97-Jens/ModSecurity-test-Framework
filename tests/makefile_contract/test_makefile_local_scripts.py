"""Keep Makefile references to local Python and shell scripts resolvable."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
CI_ROOT_SCRIPT_REFERENCE = re.compile(
    r"\$\(CI_ROOT\)/([A-Za-z0-9_./-]+\.(?:py|sh))"
)
DIRECT_LOCAL_SCRIPT_REFERENCE = re.compile(
    r"(?<![A-Za-z0-9_./*-])((?:ci|tests)/[A-Za-z0-9_./*-]+\.(?:py|sh))"
)
EXPECTED_TOOL_DEFAULTS = {
    "TRANSPORT_HARDENING_EVIDENCE_TOOL": (
        "ci/checks/evidence/check_transport_hardening_evidence.py"
    ),
    "PROTOCOL_CLIENT_TOOL": "ci/checks/protocol/protocol_client.py",
    "PROTOCOL_EVIDENCE_TOOL": "ci/checks/protocol/check_protocol_evidence.py",
}


def local_script_references(makefile: str) -> set[str]:
    """Return statically referenced local Python and shell scripts."""

    source = "\n".join(
        line for line in makefile.splitlines() if not line.lstrip().startswith("#")
    )
    references = {
        f"ci/{reference}"
        for reference in CI_ROOT_SCRIPT_REFERENCE.findall(source)
    }
    references.update(DIRECT_LOCAL_SCRIPT_REFERENCE.findall(source))
    return references


def missing_local_scripts(makefile: str) -> list[str]:
    """Return missing, escaping, or non-regular Makefile script references."""

    missing: list[str] = []
    for reference in local_script_references(makefile):
        path = Path(reference)
        if path.is_absolute() or ".." in path.parts:
            missing.append(reference)
            continue
        candidates = list(ROOT.glob(reference)) if "*" in reference else [ROOT / path]
        if not candidates or any(
            candidate.is_symlink() or not candidate.is_file()
            for candidate in candidates
        ):
            missing.append(reference)
    return sorted(missing)


class MakefileLocalScriptsTest(unittest.TestCase):
    def test_all_referenced_local_scripts_exist(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")
        references = local_script_references(makefile)

        self.assertTrue(references, "Makefile contains no local script references")
        self.assertEqual([], missing_local_scripts(makefile))

    def test_protocol_tool_defaults_use_the_maintained_underscore_runners(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")

        for variable, expected_path in EXPECTED_TOOL_DEFAULTS.items():
            with self.subTest(variable=variable):
                self.assertIn(
                    f"{variable} ?= $(CI_ROOT)/{expected_path.removeprefix('ci/')}",
                    makefile,
                )
                self.assertTrue((ROOT / expected_path).is_file(), expected_path)

    def test_missing_hyphenated_runner_is_rejected(self) -> None:
        missing = missing_local_scripts(
            "PROTOCOL_CLIENT_TOOL ?= "
            "$(CI_ROOT)/checks/protocol/protocol-client.py\n"
        )

        self.assertEqual(
            ["ci/checks/protocol/protocol-client.py"],
            missing,
        )
