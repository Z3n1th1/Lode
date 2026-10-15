from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from news.channels import discord_webhook, load_news_environment, send_discord_article
from news.pipeline import run_cycle


WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/example_token-for-offline-tests"
FEED = b"<rss><channel><item><title>Public update</title><link>https://example.com/update</link><description>Public details</description></item></channel></rss>"


class NewsChannelsTests(unittest.TestCase):
    def setUp(self) -> None:
        # Retain test artifacts inside the workspace for inspection; no cleanup
        # deletes user files or relies on the host's temporary directory.
        base = Path(__file__).resolve().parents[1] / "tmp" / "healthcheck-20261014" / "channel-tests"
        base.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="case-", dir=base))
        self.registry = self.root / "sources.json"
        self.registry.write_text(json.dumps({"schema": "IntelSources/v1", "sources": [
            {"id": "public", "provider": "rss", "url": "https://example.com/feed", "enabled": True},
        ]}), encoding="utf-8")
        self.state_dir = self.root / "state"
        self.state_path = self.state_dir / "news-state.json"
        self.env_patch = patch.dict(os.environ, {}, clear=True)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def cycle(self, **kwargs):
        return run_cycle(self.registry, self.state_dir, no_ai=True,
                         fetcher=lambda *args, **kw: FEED, **kwargs)

    def article(self):
        return next(iter(json.loads(self.state_path.read_text(encoding="utf-8"))["articles"].values()))

    def test_discord_requires_official_https_exact_webhook_path(self):
        invalid = [
            WEBHOOK.replace("https:", "http:"),
            WEBHOOK.replace("discord.com", "discord.com.evil.example"),
            WEBHOOK.replace("discord.com", "discord.com@evil.example"),
            WEBHOOK.replace("discord.com", "discord.com:443"),
            WEBHOOK.replace("/api/webhooks/", "/api/other/"),
            WEBHOOK + "/extra", WEBHOOK + "?redirect=evil", WEBHOOK + "#fragment",
        ]
        for value in invalid:
            with self.subTest(value=value), patch.dict(os.environ, {"DISCORD_WEBHOOK": value}):
                with self.assertRaisesRegex(ValueError, "official_discord_webhook_required"):
                    discord_webhook()
        for value in (WEBHOOK, WEBHOOK.replace("discord.com", "discordapp.com"),
                      WEBHOOK.replace("/api/", "/api/v10/"), WEBHOOK + "?wait=false"):
            with self.subTest(value=value), patch.dict(os.environ, {"DISCORD_WEBHOOK_URL": value}):
                self.assertTrue(discord_webhook().endswith("?wait=true"))

    def discord_post(self, status, body):
        response = Mock(status=status)
        response.read.return_value = body
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        row = {"title": "@everyone public update", "ai_summary": "<@123> summary",
               "source": "Source", "url": "https://example.com/update"}
        with patch.dict(os.environ, {"DISCORD_WEBHOOK": WEBHOOK}), \
                patch("news.channels.urllib.request.build_opener", return_value=opener) as build:
            accepted = send_discord_article(row)
        return accepted, opener, build

    def test_discord_accepts_confirmed_message_and_204_without_mentions(self):
        for status, body in ((200, b'{"id":"123456789"}'), (204, b"")):
            accepted, opener, build = self.discord_post(status, body)
            self.assertTrue(accepted)
            request = opener.open.call_args.args[0]
            payload = json.loads(request.data)
            self.assertEqual(payload["allowed_mentions"]["parse"], [])
            self.assertEqual(payload["allowed_mentions"]["users"], [])
            self.assertEqual(payload["allowed_mentions"]["roles"], [])
            self.assertFalse(payload["allowed_mentions"]["replied_user"])
            self.assertEqual(build.call_args.args[0].proxies, {})
            with self.assertRaisesRegex(ValueError, "credential_endpoint_redirect_rejected"):
                build.call_args.args[1].redirect_request(None, None, 302, "", {}, "https://evil.example")

    def test_discord_rejection_and_rate_limit_are_failures(self):
        for status, body in ((200, b'{"code":50035,"message":"invalid"}'),
                             (200, b'{"id":"123","retry_after":3}'),
                             (429, b'{"retry_after":3}'), (500, b"")):
            with self.subTest(status=status, body=body):
                self.assertFalse(self.discord_post(status, body)[0])

    def test_channels_retry_independently_and_do_not_repeat_success(self):
        feishu_sender = Mock(return_value=True)
        discord_sender = Mock(side_effect=[False, True])
        kwargs = dict(feishu=True, discord=True, sender=feishu_sender, discord_sender=discord_sender)
        failed = self.cycle(**kwargs)
        retried = self.cycle(**kwargs)
        unchanged = self.cycle(**kwargs)
        self.assertEqual(failed["channels"]["feishu"]["sent"], 1)
        self.assertEqual(failed["channels"]["discord"]["errors"], 1)
        self.assertFalse(failed["ok"])
        self.assertEqual(retried["channels"]["discord"]["sent"], 1)
        self.assertEqual(unchanged["sent"], 0)
        self.assertEqual(feishu_sender.call_count, 1)
        self.assertEqual(discord_sender.call_count, 2)
        self.assertEqual(self.article()["delivered_channels"], {"feishu": True, "discord": True})

    def test_enabling_discord_later_still_delivers_feishu_articles(self):
        feishu_sender = Mock(return_value=True)
        discord_sender = Mock(return_value=True)
        self.cycle(feishu=True, sender=feishu_sender)
        result = self.cycle(feishu=True, discord=True, sender=feishu_sender, discord_sender=discord_sender)
        self.assertEqual(result["channels"]["discord"]["sent"], 1)
        self.assertEqual(feishu_sender.call_count, 1)

    def test_legacy_delivered_flag_only_migrates_feishu(self):
        self.cycle()
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        row = next(iter(state["articles"].values()))
        row.pop("delivered_channels")
        row["delivered"] = True
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        feishu_sender = Mock(return_value=True)
        discord_sender = Mock(return_value=True)
        result = self.cycle(feishu=True, discord=True, sender=feishu_sender, discord_sender=discord_sender)
        self.assertEqual(result["sent"], 1)
        feishu_sender.assert_not_called()
        discord_sender.assert_called_once()

    def test_dry_run_does_not_call_senders_ai_or_mutate_state(self):
        self.cycle()
        original = self.state_path.read_bytes()
        summarizer = Mock(side_effect=AssertionError("must not call AI"))
        sender = Mock(side_effect=AssertionError("must not send"))
        result = run_cycle(self.registry, self.state_dir, dry_run=True, feishu=True, discord=True,
                           summarizer=summarizer, sender=sender, discord_sender=sender,
                           fetcher=lambda *args, **kw: FEED)
        self.assertEqual(original, self.state_path.read_bytes())
        self.assertEqual(result["sent"], 0)
        self.assertEqual(result["delivery_errors"], 0)
        self.assertEqual(len(result["preview"]), 1)
        summarizer.assert_not_called()
        sender.assert_not_called()

    def test_bad_channel_config_does_not_stop_collection_or_other_channel(self):
        discord_sender = Mock(return_value=True)
        result = self.cycle(feishu=True, discord=True, discord_sender=discord_sender)
        self.assertEqual(result["cached"], 1)
        self.assertEqual(result["channels"]["feishu"]["error"], "official_feishu_webhook_required")
        self.assertEqual(result["channels"]["discord"]["sent"], 1)

    def test_sender_exception_never_persists_secret_url(self):
        sender = Mock(side_effect=RuntimeError(WEBHOOK))
        result = self.cycle(discord=True, discord_sender=sender)
        self.assertNotIn("example_token", json.dumps(result))
        self.assertNotIn("example_token", self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(result["channels"]["discord"]["error"], "RuntimeError")

    def test_cache_full_preserves_pending_outbox(self):
        self.cycle(discord=True, discord_sender=Mock(return_value=False))
        old = self.article()
        state = {"articles": {"old": old}}
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        different_feed = FEED.replace(b"/update", b"/another-update")
        with patch("news.pipeline.MAX_CACHE", 1):
            result = run_cycle(self.registry, self.state_dir, no_ai=True, discord=True,
                               discord_sender=Mock(return_value=True),
                               fetcher=lambda *args, **kw: different_feed)
        self.assertEqual(result["cache_full_skipped"], 1)
        self.assertEqual(self.article()["url"], old["url"])
        self.assertEqual(result["sent"], 1)

    def test_disabled_channel_keeps_previously_queued_items(self):
        two_items = FEED.replace(b"</channel>",
                                b"<item><title>Second</title><link>https://example.com/second</link></item></channel>")
        run_cycle(self.registry, self.state_dir, no_ai=True, discord=True, max_messages=1,
                  discord_sender=Mock(return_value=True), fetcher=lambda *args, **kw: two_items)
        with patch("news.pipeline.MAX_CACHE", 1):
            result = run_cycle(self.registry, self.state_dir, no_ai=True,
                               fetcher=lambda *args, **kw: b"<rss />")
        self.assertEqual(result["cached"], 1)
        self.assertEqual(self.article()["url"], "https://example.com/second")

    def test_env_file_is_whitelisted_literal_and_preserves_process_environment(self):
        path = self.root / "news.env"
        path.write_text('FEISHU_WEBHOOK="literal-url"\nDISCORD_WEBHOOK_URL=literal-discord # note\n'
                        'DEEPSEEK_API_KEY=from-file\nUNRELATED_SECRET=ignored\n'
                        'DEEPSEEK_MODEL="$(do-not-run)"\n', encoding="utf-8")
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "existing"}):
            loaded = load_news_environment(path)
            self.assertEqual(os.environ["DEEPSEEK_API_KEY"], "existing")
            self.assertNotIn("UNRELATED_SECRET", os.environ)
            self.assertEqual(os.environ["DISCORD_WEBHOOK_URL"], "literal-discord")
            self.assertEqual(os.environ["DEEPSEEK_MODEL"], "$(do-not-run)")
            self.assertNotIn("DEEPSEEK_API_KEY", loaded)


if __name__ == "__main__":
    unittest.main()
