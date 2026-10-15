from __future__ import annotations

import json
import io
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock, patch

from intel.feishu_outbox import FeishuOutbox
from intel.feishu_sink import queue_report, send_report
from intel.models import AssetCandidate, IntelQuery, RunReport
from intel.runner import collect
from intel.providers.seed import SeedProvider
from intel.store import IntelStore
from notify.feishu_notifier import NotifyEvent, Throttler, notify, send


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "tmp" / "healthcheck-20261014"
WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/local-test-only"


def report(count: int = 1, *, is_new: bool = True, long: bool = False) -> RunReport:
    return RunReport(
        run_id="delivery-fixture", program="fixture", started_at="2026-10-14T12:00:00Z",
        completed_at="2026-10-14T12:00:01Z", provider_status=(),
        candidates=tuple(AssetCandidate(
            value=f"https://example.com/news/{index}", kind="article", source="fixture",
            title=("Long public update " * 10 if long else f"Update {index}"),
            summary=("Public source summary " * 20 if long else "Public summary"),
            score=75 if is_new else 50, is_new=is_new,
        ) for index in range(count)),
    )


class DeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        # Retain diagnostic state instead of automatically deleting test output.
        self.root = Path(tempfile.mkdtemp(prefix="intel-delivery-", dir=ARTIFACTS))

    def test_transport_parses_success_json_and_rejects_false_success(self) -> None:
        for payload, expected in (
            ({"code": 0, "msg": "success"}, True),
            ({"StatusCode": 0, "StatusMessage": "success"}, True),
            ({"code": False}, False), ({"code": "0"}, False),
            ({"code": 1, "StatusCode": 0}, False), ({"msg": "success"}, False),
            ([{"code": 0}], False),
        ):
            response = MagicMock()
            response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
            with self.subTest(payload=payload), patch("urllib.request.urlopen", return_value=response):
                self.assertEqual(expected, send(WEBHOOK, {})[0])

    def test_failed_send_does_not_consume_throttle_and_retry_does(self) -> None:
        state = self.root / "throttle.json"
        event = NotifyEvent(level="P2", title="Update", target="fixture")
        with patch("notify.feishu_notifier.send", side_effect=[(False, "simulated"), (True, "ok")]) as transport:
            first = notify(event, webhook=WEBHOOK, throttler=Throttler(state))
            self.assertFalse(first["ok"])
            self.assertFalse(state.exists())
            second = notify(event, webhook=WEBHOOK, throttler=Throttler(state))
            third = notify(event, webhook=WEBHOOK, throttler=Throttler(state))
        self.assertTrue(second["ok"])
        self.assertEqual("throttled", third["suppressed"])
        self.assertEqual(2, transport.call_count)

    def test_dry_run_never_creates_or_changes_queue_and_throttle(self) -> None:
        preview_root = self.root / "preview"
        with patch("notify.feishu_notifier.send") as transport:
            preview = send_report(report(), program="fixture", store_root=preview_root, dry_run=True)
        self.assertTrue(preview["dry_run"])
        self.assertFalse(preview_root.exists())
        transport.assert_not_called()
        with patch("notify.feishu_notifier.send", return_value=(False, "simulated")):
            send_report(report(3), program="fixture", store_root=self.root, webhook=WEBHOOK, max_items=1)
        before = (self.root / "feishu-outbox.json").read_bytes()
        with patch("notify.feishu_notifier.send") as transport:
            preview = send_report(report(0), program="fixture", store_root=self.root, dry_run=True)
        self.assertTrue(preview["dry_run"])
        self.assertEqual(before, (self.root / "feishu-outbox.json").read_bytes())
        self.assertFalse((self.root / "feishu-throttle.json").exists())
        transport.assert_not_called()

    def test_failed_delivery_survives_new_process_and_is_not_sent_twice(self) -> None:
        with patch("notify.feishu_notifier.send", return_value=(False, "simulated")):
            failed = send_report(report(), program="fixture", store_root=self.root, webhook=WEBHOOK)
        self.assertFalse(failed["ok"])
        self.assertEqual(1, failed["pending"])
        # A fresh process only sees existing/non-new candidates; it must drain
        # the durable queue without requiring the article to appear again.
        script = """
import json, sys
from unittest.mock import patch
from intel.feishu_sink import send_report
from intel.models import RunReport
report = RunReport('restart', 'fixture', '', '', (), ())
with patch('notify.feishu_notifier.send', return_value=(True, 'ok')) as transport:
    result = send_report(report, program='fixture', store_root=sys.argv[1], webhook=sys.argv[2])
    again = send_report(report, program='fixture', store_root=sys.argv[1], webhook=sys.argv[2])
print(json.dumps({'result': result, 'again': again, 'calls': transport.call_count}))
"""
        completed = subprocess.run([sys.executable, "-B", "-c", script, str(self.root), WEBHOOK],
                                   cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=True,
                                   env={**os.environ, "PYTHONUTF8": "1"}, timeout=20)
        result = json.loads(completed.stdout)
        self.assertEqual(1, result["result"]["sent_items"])
        self.assertEqual(0, result["result"]["pending"])
        self.assertEqual(0, result["again"]["sent_items"])
        self.assertEqual(1, result["calls"])

    def test_limit_and_throttle_preserve_every_untransmitted_candidate(self) -> None:
        with patch("notify.feishu_notifier.send", return_value=(True, "ok")) as transport:
            with patch("notify.feishu_notifier.time.time", return_value=10000):
                first = send_report(report(5), program="fixture", store_root=self.root,
                                    webhook=WEBHOOK, max_items=2)
                blocked = send_report(report(5, is_new=False), program="fixture", store_root=self.root,
                                      webhook=WEBHOOK, max_items=2)
            with patch("notify.feishu_notifier.time.time", return_value=11801):
                second = send_report(report(5, is_new=False), program="fixture", store_root=self.root,
                                     webhook=WEBHOOK, max_items=2)
            with patch("notify.feishu_notifier.time.time", return_value=13602):
                third = send_report(report(0), program="fixture", store_root=self.root,
                                    webhook=WEBHOOK, max_items=2)
                repeated = send_report(report(5), program="fixture", store_root=self.root,
                                       webhook=WEBHOOK, max_items=2)
        self.assertEqual((2, 3), (first["sent_items"], first["pending"]))
        self.assertEqual((0, 3), (blocked["sent_items"], blocked["pending"]))
        self.assertEqual("throttled", blocked["suppressed"])
        self.assertEqual((2, 1), (second["sent_items"], second["pending"]))
        self.assertEqual((1, 0), (third["sent_items"], third["pending"]))
        self.assertEqual(0, repeated["sent_items"])
        self.assertEqual(3, transport.call_count)

    def test_long_digest_does_not_acknowledge_truncated_entries(self) -> None:
        with patch("notify.feishu_notifier.send", return_value=(True, "ok")) as transport:
            result = send_report(report(5, long=True), program="fixture", store_root=self.root,
                                 webhook=WEBHOOK, max_items=5)
        state = FeishuOutbox(self.root).read()
        self.assertGreater(result["pending"], 0)
        self.assertEqual(5, len(state["pending"]) + len(state["delivered"]))
        self.assertEqual(result["sent_items"], len(state["delivered"]))
        payload = transport.call_args.args[1]["content"]["text"]
        self.assertEqual(result["sent_items"], payload.count("https://example.com/news/"))

    def test_concurrent_callers_cannot_send_same_batch_twice(self) -> None:
        barrier = threading.Barrier(6)

        def deliver(_: int) -> dict:
            barrier.wait(timeout=10)
            return send_report(report(2), program="fixture", store_root=self.root, webhook=WEBHOOK)

        with patch("notify.feishu_notifier.send", return_value=(True, "ok")) as transport:
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(deliver, range(6)))
        self.assertTrue(all(result["ok"] for result in results))
        self.assertEqual(2, sum(result["sent_items"] for result in results))
        self.assertEqual(1, transport.call_count)

    def test_programs_have_separate_pending_and_delivered_entries(self) -> None:
        with patch("notify.feishu_notifier.send", return_value=(False, "simulated")):
            send_report(report(), program="first", store_root=self.root, webhook=WEBHOOK)
        with patch("notify.feishu_notifier.send", return_value=(True, "ok")):
            other = send_report(report(), program="second", store_root=self.root, webhook=WEBHOOK)
        self.assertEqual(1, other["sent_items"])
        state = FeishuOutbox(self.root).read()
        self.assertEqual(["first"], [row["program"] for row in state["pending"].values()])

    def test_independent_processes_share_the_delivery_lock(self) -> None:
        script = """
import json, pathlib, sys, time
from unittest.mock import patch
from intel.feishu_sink import send_report
from intel.models import AssetCandidate, RunReport
root = pathlib.Path(sys.argv[1])
candidate = AssetCandidate(value='https://example.com/item', kind='article', source='fixture',
                           title='Public update', score=75, is_new=True)
report = RunReport('process-fixture', 'fixture', '', '', (candidate,), ())
def local_transport(*args, **kwargs):
    with (root / 'mock-transport.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'sent': True}) + '\\n')
    time.sleep(0.15)
    return True, 'ok'
with patch('notify.feishu_notifier.send', side_effect=local_transport):
    print(json.dumps(send_report(report, program='fixture', store_root=root, webhook=sys.argv[2])))
"""
        processes = [subprocess.Popen([sys.executable, "-B", "-c", script, str(self.root), WEBHOOK],
                                      cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, encoding="utf-8",
                                      env={**os.environ, "PYTHONUTF8": "1"}) for _ in range(3)]
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=20)
            self.assertEqual(0, process.returncode, stderr)
            results.append(json.loads(stdout))
        self.assertEqual(1, sum(result["sent_items"] for result in results))
        self.assertEqual(1, len((self.root / "mock-transport.jsonl").read_text(encoding="utf-8").splitlines()))

    def test_queue_and_history_crash_windows_preserve_delivery(self) -> None:
        query = IntelQuery.from_mapping({"program": "fixture", "authorization": "local fixture",
                                        "allowed_domains": ["example.com"],
                                        "seed_urls": ["https://example.com/"]})
        store = IntelStore(self.root)

        def prepare(value: RunReport) -> None:
            queue_report(value, program="fixture", store_root=self.root, min_score=0)

        # Failure before durable queue creation must not mark candidates seen.
        with patch("intel.feishu_outbox.FeishuOutbox.write", side_effect=OSError("simulated queue failure")):
            with self.assertRaises(OSError):
                collect(query, [SeedProvider()], store=store, before_persist=prepare)
        self.assertFalse(store.history_path.exists())

        # Crash after staging, before history: restarting can stage the same
        # candidate again without duplicating the pending delivery.
        with patch.object(store, "write", side_effect=OSError("simulated history failure")):
            with self.assertRaises(OSError):
                collect(query, [SeedProvider()], store=store, before_persist=prepare)
        self.assertFalse(store.history_path.exists())
        self.assertEqual(1, len(FeishuOutbox(self.root).read()["pending"]))
        collect(query, [SeedProvider()], store=IntelStore(self.root), before_persist=prepare)

        # Crash after committing history, before the network callback: the next
        # run sees an old candidate but still drains the durable pending entry.
        resumed = collect(query, [SeedProvider()], store=IntelStore(self.root), before_persist=prepare)
        self.assertFalse(resumed.candidates[0].is_new)
        with patch("notify.feishu_notifier.send", return_value=(True, "ok")) as transport:
            result = send_report(resumed, program="fixture", store_root=self.root, webhook=WEBHOOK)
            again = send_report(resumed, program="fixture", store_root=self.root, webhook=WEBHOOK)
        self.assertEqual(1, result["sent_items"])
        self.assertEqual(0, again["sent_items"])
        self.assertEqual(1, transport.call_count)

    def test_cli_stages_only_real_notifications_before_history(self) -> None:
        from intel.cli import main
        scope = ROOT / "tests" / "fixtures" / "intel" / "scope.json"
        for mode in ("collect", "watch", "preview", "real"):
            with self.subTest(mode=mode):
                state = self.root / mode
                command = "collect" if mode == "collect" else "watch"
                args = [command, "--scope", str(scope), "--out-dir", str(state), "--no-network"]
                if command == "watch":
                    args += ["--max-runs", "1"]
                if mode in {"preview", "real"}:
                    args += ["--feishu", "--feishu-min-score", "0"]
                if mode == "preview":
                    args += ["--feishu-dry-run"]

                def inspect_before_send(*_args, **_kwargs):
                    self.assertTrue((state / "history.json").exists())
                    self.assertGreater(len(FeishuOutbox(state).read()["pending"]), 0)
                    return True, "ok"

                with patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO), \
                        patch.dict(os.environ, {"FEISHU_WEBHOOK": WEBHOOK}), \
                        patch("notify.feishu_notifier.send", side_effect=inspect_before_send) as transport:
                    self.assertEqual(0, main(args))
                self.assertEqual(mode == "real", (state / "feishu-outbox.json").exists())
                self.assertEqual(1 if mode == "real" else 0, transport.call_count)


if __name__ == "__main__":
    unittest.main()
