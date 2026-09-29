"""Local regression for V7 queue pressure and Cowrie log cursor recovery."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import threading
import time
import unittest


HERE = pathlib.Path(__file__).resolve().parent
WORKSPACE_PARENT = HERE.parents[4] if len(HERE.parents) > 4 else HERE
for candidate in (
    HERE,
    pathlib.Path("/opt/model2-v6"),
    WORKSPACE_PARENT / "honeypot-analysis" / "evaluation" / "model2_v6_production_native_20260911_v1",
):
    if candidate.is_dir() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

SPEC = importlib.util.spec_from_file_location("v7_queue_backpressure_candidate", HERE / "v7_pi_observer.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def event(session: str) -> bytes:
    return (json.dumps({
        "eventid": "cowrie.session.connect",
        "session": session,
        "timestamp": "2026-09-29T00:00:00Z",
        "src_ip": "203.0.113.10",
        "src_port": 50123,
        "dst_ip": "10.148.0.2",
        "dst_port": 2222,
    }) + "\n").encode()


class QueueBackpressureTests(unittest.TestCase):
    def observer(self, root: pathlib.Path):
        log = root / "cowrie.json"
        log.write_bytes(event("a"))
        observer = MODULE.Observer({
            "cowrie_log": str(log),
            "zeek_conn_log": str(root / "conn.log"),
            "state_dir": str(root / "state"),
            "capstone_host": "127.0.0.1",
            "capstone_port": 18085,
            "max_queue_files": 1,
            "start_at_end": False,
            "transfer_ring_bases": [],
        })
        return observer, log

    def test_full_queue_does_not_advance_or_lose_event(self):
        with tempfile.TemporaryDirectory() as directory:
            observer, log = self.observer(pathlib.Path(directory))
            blocker = observer.queue_dir / "blocker.json"
            blocker.write_bytes(b"occupied")
            handle = observer._tail_once(None)
            self.assertEqual(observer.state["offset"], 0)
            self.assertEqual(observer.state["sessions"]["a"]["events"], [])
            blocker.unlink()
            handle = observer._tail_once(handle)
            self.assertEqual(observer.state["offset"], log.stat().st_size)
            self.assertEqual(len(list(observer.queue_dir.glob("*.json"))), 1)
            self.assertEqual(len(observer.state["sessions"]["a"]["events"]), 1)
            handle.close()

    def test_full_queue_does_not_switch_rotated_log_early(self):
        with tempfile.TemporaryDirectory() as directory:
            observer, log = self.observer(pathlib.Path(directory))
            blocker = observer.queue_dir / "blocker.json"
            blocker.write_bytes(b"occupied")
            handle = observer._tail_once(None)
            old_inode = observer.state["inode"]
            rotated = log.with_suffix(".1")
            log.rename(rotated)
            log.write_bytes(event("b"))
            handle = observer._tail_once(handle)
            self.assertEqual(observer.state["inode"], old_inode)
            self.assertEqual(observer.state["offset"], 0)
            blocker.unlink()
            handle = observer._tail_once(handle)
            self.assertEqual(len(observer.state["sessions"]["a"]["events"]), 1)
            self.assertNotEqual(observer.state["inode"], old_inode)
            queued = list(observer.queue_dir.glob("*.json"))
            self.assertEqual(len(queued), 1)
            queued[0].unlink()
            handle = observer._tail_once(handle)
            self.assertEqual(len(observer.state["sessions"]["b"]["events"]), 1)
            handle.close()

    def test_completion_waits_for_capacity_instead_of_being_discarded(self):
        with tempfile.TemporaryDirectory() as directory:
            observer, _ = self.observer(pathlib.Path(directory))
            blocker = observer.queue_dir / "blocker.json"
            blocker.write_bytes(b"occupied")
            result = []
            worker = threading.Thread(
                target=lambda: result.append(observer._enqueue_completion({"session_id": "a"})),
                daemon=True,
            )
            worker.start()
            time.sleep(0.05)
            self.assertEqual(result, [])
            blocker.unlink()
            worker.join(timeout=2)
            self.assertEqual(result, [True])
            self.assertEqual(len(list(observer.queue_dir.glob("*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
