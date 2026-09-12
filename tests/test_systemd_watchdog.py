from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path


NOTIFY_DIR = Path(__file__).resolve().parents[1] / "notify"
if str(NOTIFY_DIR) not in sys.path:
    sys.path.insert(0, str(NOTIFY_DIR))


class SystemdWatchdogTests(unittest.TestCase):
    def test_disabled_without_complete_systemd_environment(self) -> None:
        from systemd_watchdog import SystemdWatchdog

        notifications: list[str] = []
        watchdog = SystemdWatchdog(
            environ={},
            notify_fn=notifications.append,
        )

        watchdog.start()
        watchdog.stop()

        self.assertEqual([], notifications)

    def test_ready_and_watchdog_are_emitted_for_configured_service(self) -> None:
        from systemd_watchdog import SystemdWatchdog

        notifications: list[str] = []
        received_watchdog = threading.Event()

        def record(message: str) -> bool:
            notifications.append(message)
            if message == "WATCHDOG=1":
                received_watchdog.set()
            return True

        watchdog = SystemdWatchdog(
            environ={"NOTIFY_SOCKET": "/run/systemd/notify", "WATCHDOG_USEC": "20000"},
            notify_fn=record,
            minimum_interval_seconds=0.005,
        )
        try:
            watchdog.start(status="feishu_consumer_started")
            self.assertTrue(received_watchdog.wait(0.5), notifications)
        finally:
            watchdog.stop()

        self.assertEqual("READY=1\nSTATUS=feishu_consumer_started", notifications[0])
        self.assertIn("WATCHDOG=1", notifications)

    def test_stop_joins_the_heartbeat_thread_promptly(self) -> None:
        from systemd_watchdog import SystemdWatchdog

        watchdog = SystemdWatchdog(
            environ={"NOTIFY_SOCKET": "/run/systemd/notify", "WATCHDOG_USEC": "10000000"},
            notify_fn=lambda _: True,
        )
        watchdog.start()
        start = time.monotonic()
        watchdog.stop()

        self.assertLess(time.monotonic() - start, 0.25)


if __name__ == "__main__":
    unittest.main()
