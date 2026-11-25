"""Local commit comparison uses synthetic repositories, never remote fetches."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from stack_revision import enrich_stacks


class StackRevisionTests(unittest.TestCase):
    def git(self, *args):
        return (
            subprocess.check_output(
                ["git", "-C", str(self.root), *args], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )

    def commit(self):
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "fixture",
        )
        return self.git("rev-parse", "HEAD")

    def test_tracked_inputs_and_unavailable_history(self):
        with tempfile.TemporaryDirectory() as folder:
            self.root = Path(folder)
            self.git("init")
            (self.root / "komodo").mkdir()
            (self.root / "stack").mkdir()
            (self.root / "stack/compose.yaml").write_text("services: {}")
            (self.root / "shared").mkdir()
            (self.root / "shared/settings.yaml").write_text("initial")
            (self.root / "komodo/resources.toml").write_text(
                '[[stack]]\nname = "demo"\n[stack.config]\nserver = "host"\n'
                'linked_repo = "repo"\nrun_directory = "stack"\n'
                'config_files = [{path = "../shared/settings.yaml"}]\n'
                '[[repo]]\nname = "repo"\n[repo.config]\nrepo = "owner/repo"\n'
            )
            old = self.commit()
            (self.root / "unrelated.txt").write_text("other")
            same = self.commit()
            (self.root / "shared/settings.yaml").write_text("updated")
            changed = self.commit()
            (self.root / "stack/compose.yaml").write_text("services: {demo: {}}")
            directory_changed = self.commit()
            for latest, expected in (
                (same, "matched"),
                (changed, "changed"),
                (directory_changed, "changed"),
                ("f" * 40, "unknown"),
                ("--help", "unknown"),
            ):
                with self.subTest(latest=latest):
                    row = {
                        "kind": "stacks",
                        "name": "demo",
                        "server": "host",
                        "deployed_hash": old[:12],
                        "latest_hash": latest,
                        "revision_match": False,
                    }
                    enrich_stacks([row], self.root)
                    self.assertEqual(row["tracked_stack_inputs"], expected)
                    self.assertNotIn("owner/repo", str(row))
