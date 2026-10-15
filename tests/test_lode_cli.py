from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path

from lode import _batch_targets


class BatchTargetTests(unittest.TestCase):
    def test_target_file_keeps_order_and_drops_exact_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.txt"
            path.write_text(
                "# comment\nhttps://a.example/\nhttps://b.example/\n"
                "https://a.example/\n\n",
                encoding="utf-8",
            )
            args = argparse.Namespace(targets_file=path, from_scope=False, url=None, scope="")

            self.assertEqual(
                ["https://a.example/", "https://b.example/"],
                _batch_targets(args),
            )


if __name__ == "__main__":
    unittest.main()
