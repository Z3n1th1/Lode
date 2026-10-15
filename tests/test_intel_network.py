from __future__ import annotations

import io
import json
import os
import socket
import ssl
import unittest
from unittest.mock import Mock, patch

from intel import network


def dns_answer(*addresses: str):
    return [
        (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 443))
        for ip in addresses
    ]


class Response:
    def __init__(self, body=b"feed", *, status=200, headers=None):
        self.status = status
        self.reason = "fixture"
        self.headers = headers or {}
        self.body = io.BytesIO(body)
        self.fp = None
        self.closed = False

    def read1(self, size):
        return self.body.read1(size)

    def close(self):
        self.closed = True


def connection(response):
    result = Mock()
    result.getresponse.return_value = response
    return result


class IntelNetworkTests(unittest.TestCase):
    def test_private_special_and_fake_literal_urls_are_always_blocked(self):
        for host in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200", "198.18.1.92", "198.19.1.1", "224.0.0.1", "240.0.0.1", "[::1]", "[ff02::1]", "localhost", "foo.internal"):
            with self.subTest(host=host), self.assertRaises(network.UnsafeSourceUrl):
                network.validate_source_url(f"https://{host}/", resolve=False)

    def test_fake_ip_is_replaced_with_verified_public_answer_and_pinned(self):
        feed_connection = connection(Response())
        with patch.object(network.socket, "getaddrinfo", return_value=dns_answer("198.18.1.92")) as dns, \
             patch.object(network, "_doh_addresses", return_value=("93.184.215.14",)) as doh, \
             patch.object(network, "_connection", return_value=feed_connection) as factory:
            self.assertEqual(b"feed", network.fetch_url("https://feed.example/rss"))
        dns.assert_called_once()
        doh.assert_called_once()
        self.assertEqual(("feed.example", 443, ("93.184.215.14",)), factory.call_args.args)

    def test_private_dns_answer_cannot_trigger_doh_escape(self):
        for ips in (("10.0.0.1",), ("198.18.1.92", "127.0.0.1"), ("93.184.215.14", "169.254.169.254")):
            with self.subTest(ips=ips), \
                 patch.object(network.socket, "getaddrinfo", return_value=dns_answer(*ips)), \
                 patch.object(network, "_doh_addresses") as doh, \
                 patch.object(network, "_connection") as factory:
                with self.assertRaises(network.UnsafeSourceUrl):
                    network.fetch_url("https://feed.example/rss")
                doh.assert_not_called()
                factory.assert_not_called()

    def test_tls_and_host_identity_survive_numeric_pinning_without_dns(self):
        sock = Mock()
        context = ssl.create_default_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(ssl.CERT_REQUIRED, context.verify_mode)
        with patch.object(network.ssl, "create_default_context", return_value=context), \
             patch.object(context, "wrap_socket", return_value=sock) as wrap, \
             patch.object(network.socket, "socket", return_value=sock), \
             patch.object(network.socket, "getaddrinfo", side_effect=AssertionError("second DNS lookup")):
            conn = network._connection("feed.example", 443, ("93.184.215.14",), secure=True, deadline=network._Deadline(2))
            try:
                conn.request("GET", "/rss")
            finally:
                conn.close()
        sock.connect.assert_called_once_with(("93.184.215.14", 443))
        self.assertEqual("feed.example", wrap.call_args.kwargs["server_hostname"])
        self.assertIn(b"Host: feed.example\r\n", sock.sendall.call_args.args[0])

    def test_proxy_environment_does_not_change_connection_destination(self):
        conn = connection(Response())
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:9999", "HTTP_PROXY": "http://127.0.0.1:9999"}), \
             patch.object(network.socket, "getaddrinfo", return_value=dns_answer("93.184.215.14")), \
             patch.object(network, "_connection", return_value=conn) as factory:
            self.assertEqual(b"feed", network.fetch_url("https://feed.example/rss", headers={"Host": "127.0.0.1", "Proxy-Authorization": "secret"}))
        self.assertEqual("feed.example", factory.call_args.args[0])
        self.assertNotIn("Host", conn.request.call_args.kwargs["headers"])
        self.assertNotIn("Proxy-Authorization", conn.request.call_args.kwargs["headers"])

    def test_private_redirect_is_blocked_before_connecting(self):
        response = Response(status=302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        with patch.object(network.socket, "getaddrinfo", return_value=dns_answer("93.184.215.14")), \
             patch.object(network, "_connection", return_value=connection(response)) as factory:
            with self.assertRaises(network.UnsafeSourceUrl):
                network.fetch_url("https://feed.example/rss")
        self.assertEqual(1, factory.call_count)
        self.assertTrue(response.closed)

    def test_same_host_redirect_is_resolved_and_revalidated_again(self):
        response = Response(status=302, headers={"Location": "/new-feed"})
        with patch.object(network.socket, "getaddrinfo", side_effect=[dns_answer("93.184.215.14"), dns_answer("127.0.0.1")]) as dns, \
             patch.object(network, "_connection", return_value=connection(response)) as factory:
            with self.assertRaises(network.UnsafeSourceUrl):
                network.fetch_url("https://feed.example/rss")
        self.assertEqual(2, dns.call_count)
        self.assertEqual(1, factory.call_count)

    def test_cross_origin_redirect_does_not_leak_credentials(self):
        first = connection(Response(status=302, headers={"Location": "https://other.example/rss"}))
        second = connection(Response())
        with patch.object(network.socket, "getaddrinfo", return_value=dns_answer("93.184.215.14")), \
             patch.object(network, "_connection", side_effect=[first, second]):
            network.fetch_url("https://feed.example/rss", headers={"Authorization": "Bearer private", "Cookie": "private"})
        self.assertIn("Authorization", first.request.call_args.kwargs["headers"])
        self.assertNotIn("Authorization", second.request.call_args.kwargs["headers"])
        self.assertNotIn("Cookie", second.request.call_args.kwargs["headers"])

    def test_redirect_loop_is_bounded(self):
        with patch.object(network.socket, "getaddrinfo", return_value=dns_answer("93.184.215.14")), \
             patch.object(network, "_connection", side_effect=lambda *a, **k: connection(Response(status=302, headers={"Location": "/rss"}))) as factory:
            with self.assertRaisesRegex(ValueError, "source_too_many_redirects"):
                network.fetch_url("https://feed.example/rss")
        self.assertEqual(6, factory.call_count)

    def test_declared_and_streamed_response_sizes_are_bounded(self):
        for response in (Response(b"abcde"), Response(b"x", headers={"Content-Length": "5"})):
            with self.subTest(headers=response.headers), \
                 patch.object(network.socket, "getaddrinfo", return_value=dns_answer("93.184.215.14")), \
                 patch.object(network, "_connection", return_value=connection(response)):
                with self.assertRaisesRegex(ValueError, "source_response_too_large"):
                    network.fetch_url("https://feed.example/rss", max_bytes=4)
                self.assertTrue(response.closed)

    def test_doh_private_answer_fails_closed_without_second_resolver(self):
        payload = {"Status": 0, "Answer": [{"type": 1, "data": "169.254.169.254"}]}
        with patch.object(network, "_connection", return_value=connection(Response(json.dumps(payload).encode()))) as factory:
            with self.assertRaises(network.UnsafeSourceUrl):
                network._doh_addresses("feed.example", network._Deadline(5))
        self.assertEqual(1, factory.call_count)

    def test_doh_failure_uses_second_fixed_tls_endpoint(self):
        first = connection(Response())
        first.request.side_effect = OSError("resolver unavailable")
        payload = {"Status": 0, "Answer": [{"type": 1, "data": "93.184.215.14"}]}
        second = connection(Response(json.dumps(payload).encode()))
        with patch.object(network, "_connection", side_effect=[first, second]) as factory:
            result = network._doh_addresses("feed.example", network._Deadline(5))
        self.assertEqual(("93.184.215.14",), result)
        self.assertEqual([("dns.alidns.com", 443, ("223.5.5.5",)), ("dns.pub", 443, ("1.12.12.12",))], [call.args for call in factory.call_args_list])
        self.assertTrue(all(call.kwargs["secure"] for call in factory.call_args_list))

    def test_doh_redirect_and_oversized_response_are_not_accepted(self):
        for response in (Response(status=302, headers={"Location": "http://127.0.0.1/"}), Response(headers={"Content-Length": "65537"})):
            with self.subTest(status=response.status), \
                 patch.object(network, "_connection", return_value=connection(response)) as factory:
                with self.assertRaises(network.UnsafeSourceUrl):
                    network._doh_addresses("feed.example", network._Deadline(5))
                self.assertEqual(2, factory.call_count)

    def test_deadline_stops_a_drip_feed(self):
        response = Response(b"ab")
        deadline = Mock()
        deadline.remaining.side_effect = [1.0, TimeoutError("source_request_timed_out")]
        with self.assertRaisesRegex(TimeoutError, "source_request_timed_out"):
            network._read_bounded(response, connection(response), deadline, 10)


if __name__ == "__main__":
    unittest.main()
