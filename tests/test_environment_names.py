"""Prevent reintroducing pre-migration environment variable names."""

import ast
import re
import unittest
from pathlib import Path


class EnvironmentNamesTests(unittest.TestCase):
    def test_no_legacy_environment_names_in_python_or_deployment(self):
        root = Path(__file__).resolve().parents[1]
        legacy = re.compile(r"\b(?:YGG|CF)_[A-Z][A-Z0-9_]+\b")
        for path in root.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertIsNone(
                        legacy.search(node.value), str(path.relative_to(root))
                    )
        for path in [
            root / "compose.yaml",
            *root.glob(".github/workflows/*.yml"),
            *root.glob("scripts/*.sh"),
        ]:
            self.assertIsNone(
                legacy.search(path.read_text()), str(path.relative_to(root))
            )
