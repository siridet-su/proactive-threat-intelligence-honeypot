"""Shared, bounded process lifecycle helpers for long-running services."""

from __future__ import annotations

import signal
import threading
from contextlib import contextmanager
from types import FrameType
from typing import Any, Dict, Iterator, Optional


class ServiceLifecycle:
    """Coordinate stop requests without accepting another unit of work.

    Signal handlers only set an event.  Work already in progress is allowed to
    reach its fenced durable completion, while interruptible polling wakes
    immediately and exits before another claim is acquired.
    """

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._reason = ""
        self._reason_lock = threading.Lock()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    @property
    def reason(self) -> str:
        with self._reason_lock:
            return self._reason

    def request_stop(self, reason: str = "requested") -> None:
        with self._reason_lock:
            if not self._reason:
                self._reason = str(reason or "requested")[:64]
        self._stop.set()

    def wait(self, timeout_seconds: Optional[float] = None) -> bool:
        """Wait interruptibly; return ``True`` when shutdown was requested."""

        return self._stop.wait(timeout_seconds)

    @contextmanager
    def signal_handlers(self) -> Iterator["ServiceLifecycle"]:
        """Install SIGTERM/SIGINT handlers in the main thread and restore them."""

        previous: Dict[int, Any] = {}
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous[signum] = signal.getsignal(signum)

                def handle_signal(
                    received: int,
                    _frame: Optional[FrameType],
                    *,
                    lifecycle: "ServiceLifecycle" = self,
                ) -> None:
                    lifecycle.request_stop(signal.Signals(received).name.lower())

                signal.signal(signum, handle_signal)
        try:
            yield self
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)


def serve_http_until_stopped(
    server: Any,
    lifecycle: Optional[ServiceLifecycle] = None,
    *,
    shutdown_timeout_seconds: float = 10.0,
) -> None:
    """Serve HTTP until signalled, then stop accepting and close boundedly."""

    control = lifecycle or ServiceLifecycle()
    failure: list[BaseException] = []

    def serve() -> None:
        try:
            server.serve_forever(poll_interval=0.2)
        except BaseException as exc:  # surfaced in the main service thread
            failure.append(exc)
        finally:
            control.request_stop("server_stopped")

    thread = threading.Thread(target=serve, name="http-server", daemon=True)
    with control.signal_handlers():
        thread.start()
        while thread.is_alive() and not control.wait(0.2):
            pass
        if thread.is_alive():
            server.shutdown()
        server.server_close()
        thread.join(timeout=max(float(shutdown_timeout_seconds), 0.1))
    if thread.is_alive():
        raise RuntimeError("HTTP server did not stop within the shutdown deadline")
    if failure:
        raise failure[0]
