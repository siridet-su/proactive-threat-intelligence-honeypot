"""Regression checks for Model2 delivery health without reading envelopes."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("model2_queue_health.py")
SPEC = importlib.util.spec_from_file_location("model2_queue_health", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class QueueHealthTests(unittest.TestCase):
    def test_missing_queue_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = MODULE.inspect_queue(pathlib.Path(directory), now=200)
        self.assertEqual(result["status"], "UNAVAILABLE")

    def test_empty_queue_is_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / "queue").mkdir()
            result = MODULE.inspect_queue(pathlib.Path(directory), now=200)
        self.assertEqual(result["status"], "OK")

    def test_recent_item_is_pending(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            queue = pathlib.Path(directory) / "queue"
            queue.mkdir()
            item = queue / "0001.json"
            item.write_bytes(b"not parsed")
            os.utime(item, (150, 150))
            result = MODULE.inspect_queue(pathlib.Path(directory), now=200)
        self.assertEqual(result["status"], "PENDING")
        self.assertEqual(result["oldest_age_seconds"], 50.0)

    def test_stale_oldest_item_is_critical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            queue = pathlib.Path(directory) / "queue"
            queue.mkdir()
            first = queue / "0001.json"
            second = queue / "0002.json"
            first.touch()
            second.touch()
            os.utime(first, (1, 1))
            os.utime(second, (199, 199))
            result = MODULE.inspect_queue(pathlib.Path(directory), now=200)
        self.assertEqual(result["reason"], "delivery_stalled")
        self.assertEqual(result["queued"], 2)

    def test_capacity_is_critical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            queue = pathlib.Path(directory) / "queue"
            queue.mkdir()
            (queue / "0001.json").touch()
            result = MODULE.inspect_queue(pathlib.Path(directory), now=200, max_queue_files=1)
        self.assertEqual(result["reason"], "queue_capacity_reached")


if __name__ == "__main__":
    unittest.main()
