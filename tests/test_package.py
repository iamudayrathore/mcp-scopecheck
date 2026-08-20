"""Release identity and dependency-boundary regressions."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from mcp_scopecheck import __version__

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class PackageIdentityTests(unittest.TestCase):
    def test_release_version_is_consistent_and_runtime_dependencies_stay_empty(self) -> None:
        metadata = tomllib.loads(
            (REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]

        self.assertEqual(metadata["version"], "0.2.3")
        self.assertEqual(__version__, metadata["version"])
        self.assertEqual(metadata["dependencies"], [])


if __name__ == "__main__":
    unittest.main()
