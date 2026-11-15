from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "ci/tools/verify-mrts-update-lineage.sh"


class MrtsUpdateLineageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="mrts-lineage-")
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name) / "repository"
        self.environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        self.environment.update(
            {
                "GIT_AUTHOR_NAME": "Lineage fixture",
                "GIT_AUTHOR_EMAIL": "lineage@example.invalid",
                "GIT_COMMITTER_NAME": "Lineage fixture",
                "GIT_COMMITTER_EMAIL": "lineage@example.invalid",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
            }
        )
        self.git(
            "init", "--bare", "--object-format=sha1", str(self.repository), outside=True
        )
        self.tree = self.git("mktree", input="")
        self.current = self.commit("current")
        self.descendant = self.commit("descendant", self.current)
        self.divergent = self.commit("divergent")

    def git(
        self, *arguments: str, input: str | None = None, outside: bool = False
    ) -> str:
        command = ["git", "-c", "commit.gpgsign=false"]
        if not outside:
            command.extend(["-C", str(self.repository)])
        result = subprocess.run(
            [*command, *arguments],
            input=input,
            text=True,
            capture_output=True,
            env=self.environment,
            check=True,
        )
        return result.stdout.strip()

    def commit(self, message: str, parent: str | None = None) -> str:
        arguments = ["commit-tree", self.tree]
        if parent is not None:
            arguments.extend(["-p", parent])
        return self.git(*arguments, input=message + "\n")

    def check_lineage(self, current: str, candidate: str, *, accepted: bool) -> None:
        self.check_arguments(
            str(self.repository), current, candidate, accepted=accepted
        )

    def check_arguments(self, *arguments: str, accepted: bool = False) -> None:
        result = subprocess.run(
            ["bash", str(CHECKER), *arguments],
            text=True,
            capture_output=True,
            env=self.environment,
            check=False,
        )
        self.assertEqual(result.stdout, "")
        if accepted:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(result.stderr.startswith("verify-mrts-update-lineage: "))
            self.assertNotIn(str(self.repository), result.stderr)

    def test_accepts_same_commit(self) -> None:
        self.check_lineage(self.current, self.current, accepted=True)

    def test_accepts_descendant(self) -> None:
        self.check_lineage(self.current, self.descendant, accepted=True)

    def test_rejects_backward_update(self) -> None:
        self.check_lineage(self.descendant, self.current, accepted=False)

    def test_rejects_divergent_update(self) -> None:
        self.check_lineage(self.current, self.divergent, accepted=False)

    def test_rejects_missing_objects(self) -> None:
        for current, candidate in (
            ("0" * 40, self.descendant),
            (self.current, "0" * 40),
        ):
            with self.subTest(current=current, candidate=candidate):
                self.check_lineage(current, candidate, accepted=False)

    def test_rejects_noncommit_objects(self) -> None:
        blob = self.git("hash-object", "-w", "--stdin", input="fixture\n")
        for current, candidate in ((blob, self.descendant), (self.current, blob)):
            with self.subTest(current=current, candidate=candidate):
                self.check_lineage(current, candidate, accepted=False)

    def test_rejects_malformed_sha_arguments(self) -> None:
        for malformed in ("A" * 40, self.current[:12], "HEAD", "-" * 40):
            with self.subTest(malformed=malformed):
                self.check_lineage(malformed, self.descendant, accepted=False)
                self.check_lineage(self.current, malformed, accepted=False)

    def test_rejects_wrong_argument_count(self) -> None:
        self.check_arguments()
        self.check_arguments(
            str(self.repository), self.current, self.descendant, "extra"
        )

    def test_rejects_git_repository_error(self) -> None:
        self.check_arguments(
            str(self.repository / "missing"), self.current, self.descendant
        )

    def test_replace_ref_cannot_forge_ancestry(self) -> None:
        self.git("replace", self.divergent, self.descendant)
        # Show the fixture really fools Git when replacement objects are enabled.
        self.git("merge-base", "--is-ancestor", self.current, self.divergent)
        self.check_lineage(self.current, self.divergent, accepted=False)


if __name__ == "__main__":
    unittest.main()
