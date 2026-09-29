"""Exact socket receipts isolate two Cowrie sessions from Pi background flows."""

from __future__ import annotations

import datetime as dt
import pathlib
import sys
import unittest
from types import SimpleNamespace


RUNTIME = (
    pathlib.Path(__file__).resolve().parents[1]
    / "evaluation" / "model2_v7_32_feature_generation_20260913_v1"
    / "production_runtime_v1"
)
sys.path.insert(0, str(RUNTIME))
from v7_common import V7BoundaryError  # noqa: E402
from v7_transfer_binding import model_feature_events, select_session_bound_tuples  # noqa: E402


BASE = dt.datetime(2026, 9, 28, tzinfo=dt.timezone.utc).timestamp()


def stamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def receipt(session: str, source_port: int, *, at: float = 1.0) -> dict:
    return {
        "eventid": "cowrie.session.outbound_connection", "session": session,
        "timestamp": dt.datetime.fromtimestamp(BASE + at, dt.timezone.utc).isoformat(),
        "outbound_src_ip": "192.168.89.112", "outbound_src_port": source_port,
        "outbound_dst_ip": "93.184.215.14", "outbound_dst_port": 80,
    }


def packet(source_port: int, *, at: float = 0.8) -> SimpleNamespace:
    return SimpleNamespace(
        timestamp=BASE + at,
        tuple={"src_ip": "192.168.89.112", "src_port": source_port,
               "dst_ip": "93.184.215.14", "dst_port": 80},
        flags=0x02,
    )


class SessionSocketBindingTests(unittest.TestCase):
    def test_two_sessions_and_background_are_disjoint(self):
        packets = [packet(54001), packet(54002), packet(54003)]
        a = select_session_bound_tuples([receipt("a", 54001)], packets, stamp, BASE, BASE + 10)
        b = select_session_bound_tuples([receipt("b", 54002)], packets, stamp, BASE, BASE + 10)
        self.assertEqual([x["src_port"] for x in a], [54001])
        self.assertEqual([x["src_port"] for x in b], [54002])
        self.assertNotIn(54003, [x["src_port"] for x in a + b])

    def test_missing_or_ambiguous_syn_fails_closed(self):
        with self.assertRaisesRegex(V7BoundaryError, "session_socket_syn_binding_invalid"):
            select_session_bound_tuples([receipt("a", 54001)], [], stamp, BASE, BASE + 10)
        with self.assertRaisesRegex(V7BoundaryError, "session_socket_syn_binding_invalid"):
            select_session_bound_tuples([receipt("a", 54001)], [packet(54001), packet(54001)], stamp, BASE, BASE + 10)

    def test_wrong_session_receipt_or_invalid_boundary_fails_closed(self):
        with self.assertRaisesRegex(V7BoundaryError, "session_socket_event_session_mismatch"):
            select_session_bound_tuples(
                [receipt("a", 54001), receipt("b", 54002)],
                [packet(54001), packet(54002)], stamp, BASE, BASE + 10,
            )
        bad = receipt("a", 54001)
        bad["outbound_dst_ip"] = "10.0.0.1"
        with self.assertRaisesRegex(V7BoundaryError, "session_socket_boundary_invalid"):
            select_session_bound_tuples([bad], [packet(54001)], stamp, BASE, BASE + 10)
        with self.assertRaisesRegex(V7BoundaryError, "session_socket_receipt_duplicate"):
            select_session_bound_tuples([receipt("a", 54001)] * 2, [packet(54001)], stamp, BASE, BASE + 10)

    def test_receipt_cannot_precede_syn_or_arrive_much_later(self):
        for at in (0.1, 10.0):
            with self.assertRaisesRegex(V7BoundaryError, "session_socket_syn_binding_invalid"):
                select_session_bound_tuples([receipt("a", 54001, at=at)], [packet(54001)], stamp, BASE, BASE + 15)

    def test_no_receipt_never_claims_background_flow(self):
        self.assertEqual(select_session_bound_tuples([], [packet(54003)], stamp, BASE, BASE + 10), [])
        https_metadata_only = {
            "eventid": "cowrie.session.outbound_connection", "session": "a",
            "timestamp": dt.datetime.fromtimestamp(BASE + 1, dt.timezone.utc).isoformat(),
        }
        self.assertEqual(
            select_session_bound_tuples([https_metadata_only], [packet(54003)], stamp, BASE, BASE + 10),
            [],
        )

    def test_socket_receipts_do_not_change_model_event_sequence(self):
        command = {"eventid": "cowrie.command.input", "session": "a"}
        events, hashes = model_feature_events(
            [command, receipt("a", 54001)], ["a" * 64, "b" * 64]
        )
        self.assertEqual(events, [command])
        self.assertEqual(hashes, ["a" * 64])
        with self.assertRaisesRegex(V7BoundaryError, "source_event_hashes_missing"):
            model_feature_events([command], [])


if __name__ == "__main__":
    unittest.main()
