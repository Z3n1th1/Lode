#!/usr/bin/env python3
"""Small stdlib-only systemd readiness and watchdog notifier."""
from __future__ import annotations

import os
import socket
import threading
from typing import Any, Callable, Mapping, Optional


def notify_systemd(message: str, *, environ: Optional[Mapping[str, str]] = None) -> bool:
    """Send one datagram to systemd when this process has a notify socket."""
    values = os.environ if environ is None else environ
    notify_socket = str(values.get("NOTIFY_SOCKET", "")).strip()
    if not notify_socket or not hasattr(socket, "AF_UNIX"):
        return False
    address = "\0" + notify_socket[1:] if notify_socket.startswith("@") else notify_socket
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
            client.sendto(message.encode("utf-8"), address)
    except OSError:
        return False
    return True


class SystemdWatchdog:
    """Emit bounded systemd heartbeats and release its thread on service exit."""

    def __init__(
        self,
        *,
        environ: Optional[Mapping[str, str]] = None,
        notify_fn: Optional[Callable[[str], Any]] = None,
        minimum_interval_seconds: float = 1.0,
    ) -> None:
        if minimum_interval_seconds <= 0:
            raise ValueError("minimum_interval_seconds_must_be_positive")
        self._environ = dict(os.environ if environ is None else environ)
        self._notify_fn = notify_fn or (lambda message: notify_systemd(message, environ=self._environ))
        self._minimum_interval_seconds = float(minimum_interval_seconds)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._interval_seconds = self._watchdog_interval_seconds()

    def _watchdog_interval_seconds(self) -> Optional[float]:
        if not str(self._environ.get("NOTIFY_SOCKET", "")).strip():
            return None
        try:
            watchdog_usec = int(str(self._environ.get("WATCHDOG_USEC", "0")))
        except ValueError:
            return None
        if watchdog_usec <= 0:
            return None
        return max(self._minimum_interval_seconds, watchdog_usec / 2_000_000)

    def start(self, *, status: str = "running") -> None:
        """Declare readiness, then emit heartbeats at half the watchdog interval."""
        if self._interval_seconds is None:
            return
        with self._lock:
            if self._thread is not None:
                return
            self._notify_fn(f"READY=1\nSTATUS={status[:200]}")
            self._thread = threading.Thread(target=self._run, name="systemd-watchdog", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Wake and join the heartbeat thread; never hold it past process shutdown."""
        with self._lock:
            thread = self._thread
            self._thread = None
            self._stop.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)

    def _run(self) -> None:
        assert self._interval_seconds is not None
        while not self._stop.wait(self._interval_seconds):
            self._notify_fn("WATCHDOG=1")
