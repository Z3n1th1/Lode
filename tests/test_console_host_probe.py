"""The 运行 page's host probe must work on win / macos / linux.

It used to read /proc/meminfo and shell out to `systemctl is-active` for five
hardcoded `pa-*` unit names, with every failure swallowed -- so off Linux the page
could only ever render dashes, which reads like "everything is down" rather than
"this box isn't Linux". These tests pin each platform's branch with an injected
runner/fixture, plus the real Windows call on a Windows host.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

PENTEST_AGENT = Path(__file__).resolve().parents[1]
if str(PENTEST_AGENT) not in sys.path:
    sys.path.insert(0, str(PENTEST_AGENT))

from console.projections import (  # noqa: E402
    MONITORED_SERVICES_ENV,
    host_memory,
    monitored_services,
    service_states,
)

MEMINFO_FIXTURE = """MemTotal:       32761916 kB
MemFree:         1234567 kB
MemAvailable:   16384640 kB
Buffers:          123456 kB
"""


class FakeDone:
    def __init__(self, stdout: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode


class RecordingRunner:
    """Stands in for subprocess.run; answers by the program name in argv."""

    def __init__(self, responses: dict[str, FakeDone]) -> None:
        self.responses = responses
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):  # noqa: ANN001, ANN003
        self.calls.append(list(argv))
        return self.responses.get(argv[0], FakeDone("", 1))


class HostMemoryTests(unittest.TestCase):
    def test_linux_reads_proc_meminfo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            meminfo = Path(tmp) / "meminfo"
            meminfo.write_text(MEMINFO_FIXTURE, encoding="utf-8")
            mem = host_memory("linux", linux_meminfo=meminfo)
        self.assertEqual(32761916 // 1024, mem["total_mb"])
        self.assertEqual(16384640 // 1024, mem["avail_mb"])
        self.assertEqual(round((32761916 - 16384640) * 100 / 32761916), mem["used_pct"])

    def test_linux_without_proc_meminfo_is_empty_not_zero(self) -> None:
        # 不编造 0:0 会画成"内存用满", {} 才会让界面显示横线
        mem = host_memory("linux", linux_meminfo="/nonexistent/proc/meminfo")
        self.assertEqual({}, mem)

    def test_macos_reads_sysctl_and_vm_stat(self) -> None:
        vm_stat = (
            "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
            "Pages free:                          100000.\n"
            "Pages active:                        200000.\n"
            "Pages inactive:                       50000.\n"
            "Pages speculative:                    10000.\n"
        )
        runner = RecordingRunner({
            "sysctl": FakeDone(f"{16 * 1024 ** 3}\n"),
            "vm_stat": FakeDone(vm_stat),
        })
        mem = host_memory("darwin", run=runner)
        self.assertEqual(16384, mem["total_mb"])
        # (free + inactive + speculative) * 16KiB; active pages are not "available"
        self.assertEqual((100000 + 50000 + 10000) * 16384 // (1024 * 1024), mem["avail_mb"])
        self.assertEqual(["sysctl", "vm_stat"], [call[0] for call in runner.calls])

    def test_macos_without_sysctl_output_is_empty(self) -> None:
        mem = host_memory("darwin", run=RecordingRunner({}))
        self.assertEqual({}, mem)

    def test_unknown_platform_is_empty(self) -> None:
        self.assertEqual({}, host_memory("plan9"))

    def test_zero_total_memory_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            meminfo = Path(tmp) / "meminfo"
            meminfo.write_text("MemTotal: 0 kB\nMemAvailable: 0 kB\n", encoding="utf-8")
            self.assertEqual({}, host_memory("linux", linux_meminfo=meminfo))

    @unittest.skipUnless(sys.platform.startswith("win"), "asserts the real Windows API path")
    def test_windows_reads_real_memory(self) -> None:
        mem = host_memory()
        self.assertGreater(mem["total_mb"], 0)
        self.assertGreaterEqual(mem["avail_mb"], 0)
        self.assertLessEqual(mem["avail_mb"], mem["total_mb"])
        self.assertTrue(0 <= mem["used_pct"] <= 100)


class MonitoredServicesTests(unittest.TestCase):
    def test_env_var_is_parsed_and_trimmed(self) -> None:
        with unittest.mock.patch.dict(os.environ, {MONITORED_SERVICES_ENV: " nginx , lode-agent ,, "}):
            self.assertEqual(("nginx", "lode-agent"), monitored_services())

    def test_unset_means_monitor_nothing(self) -> None:
        # 以前的五个 pa-* 名字是某台机器的私事,现在默认一个都不盯,
        # 前端「服务」那一段就自己消失
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(MONITORED_SERVICES_ENV, None)
            self.assertEqual((), monitored_services())
            self.assertEqual({}, service_states(monitored_services()))

    def test_linux_maps_is_active_output(self) -> None:
        runner = RecordingRunner({"systemctl": FakeDone("active\n")})
        self.assertEqual({"nginx": "active"}, service_states(["nginx"], platform_name="linux", run=runner))
        self.assertEqual(["systemctl", "is-active", "nginx"], runner.calls[0])

    def test_macos_uses_launchctl_exit_code(self) -> None:
        runner = RecordingRunner({"launchctl": FakeDone("", 0)})
        self.assertEqual({"x": "active"}, service_states(["x"], platform_name="darwin", run=runner))
        runner = RecordingRunner({"launchctl": FakeDone("", 113)})
        self.assertEqual({"x": "inactive"}, service_states(["x"], platform_name="darwin", run=runner))

    def test_windows_parses_sc_query_state(self) -> None:
        running = FakeDone("STATE : 4  RUNNING\n")
        stopped = FakeDone("STATE : 1  STOPPED\n")
        runner = RecordingRunner({"sc": running})
        self.assertEqual({"w": "active"}, service_states(["w"], platform_name="win32", run=runner))
        runner = RecordingRunner({"sc": stopped})
        self.assertEqual({"w": "inactive"}, service_states(["w"], platform_name="win32", run=runner))
        runner = RecordingRunner({"sc": FakeDone("no such service\n", 1060)})
        self.assertEqual({"w": "unknown"}, service_states(["w"], platform_name="win32", run=runner))

    def test_probe_failure_does_not_sink_the_others(self) -> None:
        class Exploding:
            def __call__(self, argv, **kwargs):  # noqa: ANN001, ANN003
                if argv[-1] == "bad":
                    raise OSError("boom")
                return FakeDone("active\n")

        self.assertEqual({"good": "active", "bad": "n/a"},
                         service_states(["good", "bad"], platform_name="linux", run=Exploding()))

    def test_unknown_platform_reports_na_per_service(self) -> None:
        self.assertEqual({"x": "n/a"}, service_states(["x"], platform_name="plan9"))


class SystemProjectionTests(unittest.TestCase):
    def test_scheduler_contract_is_unchanged(self) -> None:
        """前端 SchedulerInfo 读这些键;这次改动只换 mem/services 的来源。"""
        from console.projections import ReadOnlyControlPlane

        with tempfile.TemporaryDirectory() as tmp:
            plane = ReadOnlyControlPlane(tmp)
            system = plane.system()
        self.assertEqual(
            {"rss_last_run", "rss_seen", "rss_last_notified", "rss_last_new",
             "keyleak_last_run", "keyleak_status", "gh_events_last_run",
             "gh_events_status", "gh_events_poll", "socks_last_run", "socks_status"},
            set(system["scheduler"]),
        )
        self.assertIn("mem", system)
        self.assertIn("services", system)
        self.assertEqual({}, system["services"])


if __name__ == "__main__":
    unittest.main()
