#!/usr/bin/env python3
"""Bounded public decoy sensor matching the frozen V7 T1046 exchange."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import signal
import socket
import threading
import time


PORTS = (80, 443, 445, 3306)
BANNER = b"MODEL2-V7-BOUNDARY\n"
MAX_REQUEST = 4096


class Sensor:
    def __init__(self, bind: str, receipt: pathlib.Path) -> None:
        self.bind = bind
        self.receipt = receipt
        self.stop = threading.Event()
        self.sockets: list[socket.socket] = []
        self.lock = threading.Lock()

    def record(self, value: dict[str, object]) -> None:
        line = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
        with self.lock:
            self.receipt.parent.mkdir(parents=True, exist_ok=True)
            with self.receipt.open("ab") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())

    def serve(self, listener: socket.socket, port: int) -> None:
        while not self.stop.is_set():
            try:
                connection, peer = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            started = time.time()
            sent = received = 0
            try:
                connection.settimeout(1.0)
                connection.sendall(BANNER)
                sent = len(BANNER)
                try:
                    received = len(connection.recv(MAX_REQUEST))
                except (TimeoutError, OSError):
                    pass
            except OSError:
                pass
            finally:
                try:
                    local = connection.getsockname()
                except OSError:
                    local = (self.bind, port)
                connection.close()
            self.record({
                "schema_version": "model2_v7_t1046_sensor_receipt.v1",
                "source_ip": str(peer[0]), "source_port": int(peer[1]),
                "target_ip": str(local[0]), "target_port": port,
                "started_epoch": started, "finished_epoch": time.time(),
                "orig_payload_bytes": received, "response_bytes": sent,
            })

    def run(self) -> None:
        for port in PORTS:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.bind, port))
            listener.listen(32)
            listener.settimeout(0.5)
            self.sockets.append(listener)
            threading.Thread(target=self.serve, args=(listener, port), daemon=True).start()
        while not self.stop.wait(0.5):
            pass

    def shutdown(self, *_: object) -> None:
        self.stop.set()
        for listener in self.sockets:
            try:
                listener.close()
            except OSError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--receipt", type=pathlib.Path, required=True)
    args = parser.parse_args()
    sensor = Sensor(args.bind, args.receipt)
    signal.signal(signal.SIGTERM, sensor.shutdown)
    signal.signal(signal.SIGINT, sensor.shutdown)
    sensor.run()


if __name__ == "__main__":
    main()
